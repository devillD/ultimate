import http from 'node:http';
import https from 'node:https';
import { Transform } from 'node:stream';
import { MapHeaderNamesFromArray, RawHeaderNames } from './HeaderUtil.mjs';
import { decode_protocol } from './EncodeProtocol.mjs';
import { Response } from './Response.mjs';
import { randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import {
    validateDestinationUrl,
    resolveAndValidateHost,
    sanitizeContentDisposition,
    isBlockedMimeType,
} from './Security.mjs';

const randomBytesAsync = promisify(randomBytes);

// Connection agents with keep-alive to minimize handshake overhead
const http_agent = new http.Agent({
    keepAlive: true,
    maxSockets: 50,
    timeout: 30000,
});

const https_agent = new https.Agent({
    keepAlive: true,
    maxSockets: 50,
    timeout: 30000,
});

// Maximum allowable transfer size per single streamed request (150 MB)
const MAX_STREAM_BYTES = 150 * 1024 * 1024;

/**
 * Creates a stream limiter that counts bytes transferred and aborts the stream
 * if it exceeds the maximum allowable transfer budget.
 *
 * @param {number} maxBytes - Maximum byte limit before aborting.
 * @returns {Transform} Node.js Transform stream.
 */
function createStreamLimiter(maxBytes = MAX_STREAM_BYTES) {
    let transferred = 0;
    return new Transform({
        transform(chunk, encoding, callback) {
            transferred += chunk.length;
            if (transferred > maxBytes) {
                const error = new Error(`Bandwidth limit exceeded (${Math.round(maxBytes / 1024 / 1024)}MB max per stream).`);
                error.code = 'ERR_STREAM_LIMIT_EXCEEDED';
                return callback(error);
            }
            callback(null, chunk);
        },
    });
}

/**
 * Performs an upstream HTTP or HTTPS request, streaming the client request body
 * to the remote server and returning the upstream response stream.
 *
 * Jargon definition: "Streaming" means passing data chunk-by-chunk as it arrives over the
 * network, rather than waiting to load the entire multi-megabyte file into memory first.
 *
 * @param {http.IncomingMessage} server_request - Client request stream.
 * @param {Object} request_headers - Sanitized headers to send to upstream.
 * @param {Object} url - Remote destination object { host, port, protocol, path }.
 * @param {string} resolvedIp - Validated safe public IP address for SSRF protection.
 * @returns {Promise<http.IncomingMessage>} Resolves with the upstream response stream.
 */
async function Fetch(server_request, request_headers, url, resolvedIp) {
    const hostHeader = (url.port && url.port !== 80 && url.port !== 443) ? `${url.host}:${url.port}` : url.host;
    
    // Clean hop-by-hop and conflicting headers
    delete request_headers['connection'];
    delete request_headers['transfer-encoding'];
    delete request_headers['keep-alive'];
    delete request_headers['expect'];
    delete request_headers['upgrade'];
    delete request_headers['host'];
    request_headers['host'] = hostHeader;
    request_headers['Host'] = hostHeader;

    const options = {
        host: url.host,
        port: url.port,
        path: url.path,
        method: server_request.method,
        headers: request_headers,
        timeout: 30000,
    };

    // Ensure Server Name Indication (SNI) matches target hostname
    if (url.protocol === 'https:') {
        options.servername = url.host;
    }

    let outgoing;

    if (url.protocol === 'https:') {
        outgoing = https.request({ ...options, agent: https_agent });
    } else if (url.protocol === 'http:') {
        outgoing = http.request({ ...options, agent: http_agent });
    } else {
        throw new RangeError(`Unsupported protocol: '${url.protocol}'`);
    }

    // Body handling: for bodyless methods, end immediately.
    // For methods with body (POST, PUT, PATCH), pipe if not ended, or end if already ended.
    const isBodyless = server_request.method === 'GET' || server_request.method === 'HEAD' || server_request.method === 'OPTIONS';
    if (isBodyless || server_request.readableEnded) {
        outgoing.end();
    } else {
        server_request.pipe(outgoing);
    }

    return await new Promise((resolve, reject) => {
        outgoing.on('response', resolve);
        outgoing.on('error', reject);
        outgoing.on('timeout', () => {
            outgoing.destroy(new Error('Upstream connection timed out'));
        });
        server_request.on('error', (err) => {
            outgoing.destroy(err);
        });
    });
}

/**
 * Copies forwarded client headers into the target header object, preserving
 * the original casing.
 *
 * @param {http.IncomingMessage} request - Incoming server request.
 * @param {Array<string>} forward - Array of header names to forward.
 * @param {Object} target - Target headers object.
 */
function load_forwarded_headers(request, forward, target) {
    const raw = RawHeaderNames(request.rawHeaders);

    for (const header of forward) {
        for (const cap of raw) {
            if (cap.toLowerCase() === header.toLowerCase()) {
                target[cap] = request.headers[header.toLowerCase()];
            }
        }
    }
}

/**
 * Reads and decodes Bare request headers sent by Ultraviolet.
 *
 * @param {http.IncomingMessage} server_request - Client request.
 * @param {Object} request_headers - Request headers map.
 * @returns {{error?: Object, remote?: Object, headers?: Object}}
 */
function read_headers(server_request, request_headers) {
    const remote = Object.setPrototypeOf({}, null);
    const headers = Object.setPrototypeOf({}, null);

    for (const remote_prop of ['host', 'port', 'protocol', 'path']) {
        const header = `x-bare-${remote_prop}`;

        if (header in request_headers) {
            let value = request_headers[header];

            if (remote_prop === 'port') {
                value = parseInt(value, 10);
                if (isNaN(value)) {
                    return {
                        error: {
                            code: 'INVALID_BARE_HEADER',
                            id: `request.headers.${header}`,
                            message: 'Header was not a valid integer.',
                        },
                    };
                }
            }

            remote[remote_prop] = value;
        } else {
            return {
                error: {
                    code: 'MISSING_BARE_HEADER',
                    id: `request.headers.${header}`,
                    message: 'Header was not specified.',
                },
            };
        }
    }

    if ('x-bare-headers' in request_headers) {
        let json;

        try {
            json = JSON.parse(request_headers['x-bare-headers']);

            for (const header in json) {
                if (typeof json[header] !== 'string' && !Array.isArray(json[header])) {
                    return {
                        error: {
                            code: 'INVALID_BARE_HEADER',
                            id: `bare.headers.${header}`,
                            message: 'Header was not a String or Array.',
                        },
                    };
                }
            }
        } catch (err) {
            return {
                error: {
                    code: 'INVALID_BARE_HEADER',
                    id: 'request.headers.x-bare-headers',
                    message: `Header contained invalid JSON. (${err.message})`,
                },
            };
        }

        Object.assign(headers, json);
    } else {
        return {
            error: {
                code: 'MISSING_BARE_HEADER',
                id: 'request.headers.x-bare-headers',
                message: 'Header was not specified.',
            },
        };
    }

    if ('x-bare-forward-headers' in request_headers) {
        let json;

        try {
            json = JSON.parse(request_headers['x-bare-forward-headers']);
        } catch (err) {
            return {
                error: {
                    code: 'INVALID_BARE_HEADER',
                    id: 'request.headers.x-bare-forward-headers',
                    message: `Header contained invalid JSON. (${err.message})`,
                },
            };
        }

        load_forwarded_headers(server_request, json, headers);
    } else {
        return {
            error: {
                code: 'MISSING_BARE_HEADER',
                id: 'request.headers.x-bare-forward-headers',
                message: 'Header was not specified.',
            },
        };
    }

    return { remote, headers };
}

/**
 * Handles Bare V1 HTTP proxy requests from Ultraviolet.
 * Implements SSRF filtering, Range streaming, download blocking, and header sanitation.
 *
 * @param {Server} server - Bare server instance.
 * @param {http.IncomingMessage} server_request - Client request.
 * @returns {Promise<Response>}
 */
export async function v1(server, server_request) {
    const response_headers = Object.setPrototypeOf({}, null);

    response_headers['x-robots-tag'] = 'noindex';
    response_headers['access-control-allow-headers'] = '*';
    response_headers['access-control-allow-origin'] = '*';
    response_headers['access-control-expose-headers'] = '*';

    const { error, remote, headers } = read_headers(server_request, server_request.headers);

    if (error) {
        if (server_request.method === 'OPTIONS') {
            return new Response(undefined, 200, response_headers);
        }
        return server.json(400, error);
    }

    // 1. Strict URL structural validation
    const destError = validateDestinationUrl(remote);
    if (destError) {
        return server.json(403, destError);
    }

    // 2. SSRF check with pre-flight safe DNS resolution
    const dnsResult = await resolveAndValidateHost(remote.host);
    if (!dnsResult.safe) {
        return server.json(403, dnsResult.error);
    }

    // Ensure normal desktop browser headers are present if missing
    if (!headers['user-agent'] && !headers['User-Agent']) {
        headers['User-Agent'] = server_request.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
    }

    let upstreamResponse;

    try {
        upstreamResponse = await Fetch(server_request, headers, remote, dnsResult.resolvedIp);
    } catch (err) {
        if (err instanceof Error) {
            switch (err.code) {
                case 'ENOTFOUND':
                    return server.json(500, {
                        code: 'HOST_NOT_FOUND',
                        id: 'request',
                        message: 'The specified host could not be resolved.',
                    });
                case 'ECONNREFUSED':
                    return server.json(500, {
                        code: 'CONNECTION_REFUSED',
                        id: 'response',
                        message: 'The remote rejected the connection.',
                    });
                case 'ECONNRESET':
                    return server.json(500, {
                        code: 'CONNECTION_RESET',
                        id: 'response',
                        message: 'The connection was forcibly closed by the remote server.',
                    });
                case 'ETIMEOUT':
                case 'ETIMEDOUT':
                    return server.json(504, {
                        code: 'CONNECTION_TIMEOUT',
                        id: 'response',
                        message: 'The upstream server response timed out.',
                    });
            }
        }
        throw err;
    }

    // 3. Download Blocking (MIME Type Check)
    const contentType = upstreamResponse.headers['content-type'];
    if (isBlockedMimeType(contentType)) {
        upstreamResponse.destroy(); // Cancel upstream stream immediately to save bandwidth
        return server.json(403, {
            code: 'DOWNLOAD_FORBIDDEN',
            id: 'response.security.download',
            message: 'Direct downloads of binary and executable files are strictly disabled on this proxy.',
        });
    }

    // 4. Sanitize Content-Disposition (Strip attachment directive)
    if (upstreamResponse.headers['content-disposition']) {
        upstreamResponse.headers['content-disposition'] = sanitizeContentDisposition(upstreamResponse.headers['content-disposition']);
    }

    // 5. Forward essential headers and Range information
    for (const header in upstreamResponse.headers) {
        const lower = header.toLowerCase();
        if (lower === 'content-encoding' || lower === 'x-content-encoding') {
            response_headers['content-encoding'] = upstreamResponse.headers[header];
        } else if (lower === 'content-length') {
            response_headers['content-length'] = upstreamResponse.headers[header];
        } else if (lower === 'content-range') {
            response_headers['content-range'] = upstreamResponse.headers[header];
        } else if (lower === 'accept-ranges') {
            response_headers['accept-ranges'] = upstreamResponse.headers[header];
        }
    }

    // Map headers back for Ultraviolet client
    response_headers['x-bare-headers'] = JSON.stringify(
        MapHeaderNamesFromArray(RawHeaderNames(upstreamResponse.rawHeaders), { ...upstreamResponse.headers })
    );
    response_headers['x-bare-status'] = upstreamResponse.statusCode;
    response_headers['x-bare-status-text'] = upstreamResponse.statusMessage;

    // Attach stream limiter (O(1) memory) to prevent single-stream monopolization
    const limitedStream = upstreamResponse.pipe(createStreamLimiter(MAX_STREAM_BYTES));

    // Handle stream limiter errors cleanly
    limitedStream.on('error', (err) => {
        upstreamResponse.destroy(err);
    });

    return new Response(limitedStream, 200, response_headers);
}

// Temporary metadata storage for WebSocket upgrades
const temp_meta = Object.setPrototypeOf({}, null);

// Cleanup expired WebSocket metadata every 5 seconds
const metaCleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const id in temp_meta) {
        if (temp_meta[id].expires < now) {
            delete temp_meta[id];
        }
    }
}, 5000);

if (metaCleanupInterval.unref) {
    metaCleanupInterval.unref();
}

export async function v1wsmeta(server, server_request) {
    if (!('x-bare-id' in server_request.headers)) {
        return server.json(400, {
            code: 'MISSING_BARE_HEADER',
            id: 'request.headers.x-bare-id',
            message: 'Header was not specified',
        });
    }

    const id = server_request.headers['x-bare-id'];

    if (!(id in temp_meta)) {
        return server.json(400, {
            code: 'INVALID_BARE_HEADER',
            id: 'request.headers.x-bare-id',
            message: 'Unregistered ID or metadata expired',
        });
    }

    const { meta } = temp_meta[id];
    delete temp_meta[id];

    if (typeof meta === 'undefined') {
        return server.json(200, null);
    }

    return server.json(200, meta);
}

export async function v1wsnewmeta(server, server_request) {
    const id = (await randomBytesAsync(32)).toString('hex');

    temp_meta[id] = {
        expires: Date.now() + 30e3,
    };

    return new Response(Buffer.from(id));
}

/**
 * Proxies WebSocket upgrade requests through the Bare server with concurrency tracking and SSRF checks.
 *
 * @param {Server} server - Bare server instance.
 * @param {http.IncomingMessage} server_request - Client upgrade request.
 * @param {net.Socket} server_socket - Client TCP socket.
 * @param {Buffer} server_head - Initial upgrade payload buffer.
 */
export async function v1socket(server, server_request, server_socket, server_head) {
    if (!server_request.headers['sec-websocket-protocol']) {
        server_socket.end();
        return;
    }

    const [first_protocol, data] = server_request.headers['sec-websocket-protocol'].split(/,\s*/g);

    if (first_protocol !== 'bare') {
        server_socket.end();
        return;
    }

    let parsed;
    try {
        parsed = JSON.parse(decode_protocol(data));
    } catch {
        server_socket.end();
        return;
    }

    const { remote, headers, forward_headers, id } = parsed;

    // Check WebSocket concurrency limit
    if (server.activeWebSockets >= server.maxWebSockets) {
        server.error(`WebSocket concurrency cap reached (${server.activeWebSockets}/${server.maxWebSockets}). Rejecting.`);
        server_socket.write('HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\n\r\n');
        server_socket.end();
        return;
    }

    // SSRF validation for WebSocket destination
    const destError = validateDestinationUrl(remote);
    if (destError) {
        server.error('SSRF blocked WebSocket destination:', destError.message);
        server_socket.end();
        return;
    }

    const dnsResult = await resolveAndValidateHost(remote.host);
    if (!dnsResult.safe) {
        server.error('SSRF blocked WebSocket IP resolution:', dnsResult.error.message);
        server_socket.end();
        return;
    }

    load_forwarded_headers(server_request, forward_headers, headers);

    const hostHeader = (remote.port && remote.port !== 80 && remote.port !== 443) ? `${remote.host}:${remote.port}` : remote.host;
    headers['host'] = hostHeader;
    headers['Host'] = hostHeader;

    const options = {
        host: dnsResult.resolvedIp || remote.host,
        port: remote.port,
        path: remote.path,
        headers,
        method: server_request.method,
        timeout: 30000,
    };

    if (remote.protocol === 'wss:') {
        options.servername = remote.host;
    }

    let request_stream;

    const response_promise = new Promise((resolve, reject) => {
        try {
            if (remote.protocol === 'wss:') {
                request_stream = https.request({ ...options, agent: https_agent }, () => {
                    reject(new Error("Remote didn't upgrade the WebSocket request"));
                });
            } else if (remote.protocol === 'ws:') {
                request_stream = http.request({ ...options, agent: http_agent }, () => {
                    reject(new Error("Remote didn't upgrade the WebSocket request"));
                });
            } else {
                return reject(new RangeError(`Unsupported protocol: '${remote.protocol}'`));
            }

            request_stream.on('upgrade', (...args) => resolve(args));
            request_stream.on('error', reject);
            request_stream.write(server_head);
            request_stream.end();
        } catch (err) {
            reject(err);
        }
    });

    let upgradeArgs;
    try {
        upgradeArgs = await response_promise;
    } catch (err) {
        server.error('WebSocket upgrade failed:', err.message || err);
        server_socket.end();
        return;
    }

    const [response, socket, head] = upgradeArgs;

    // Track active WebSocket
    server.activeWebSockets += 1;

    const cleanup = () => {
        server.activeWebSockets = Math.max(0, server.activeWebSockets - 1);
    };

    socket.once('close', cleanup);
    server_socket.once('close', cleanup);

    if (id in temp_meta) {
        if (typeof id === 'string') {
            temp_meta[id].meta = {
                headers: MapHeaderNamesFromArray(RawHeaderNames(response.rawHeaders), { ...response.headers }),
            };
        }
    }

    const response_headers = [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        'Sec-WebSocket-Protocol: bare',
        `Sec-WebSocket-Accept: ${response.headers['sec-websocket-accept']}`,
    ];

    if ('sec-websocket-extensions' in response.headers) {
        response_headers.push(`Sec-WebSocket-Extensions: ${response.headers['sec-websocket-extensions']}`);
    }

    server_socket.write(response_headers.concat('', '').join('\r\n'));
    server_socket.write(head);

    socket.on('close', () => server_socket.end());
    server_socket.on('close', () => socket.end());

    socket.on('error', (err) => {
        server.error('Remote WebSocket error:', err.message);
        server_socket.end();
    });

    server_socket.on('error', (err) => {
        server.error('Serving WebSocket error:', err.message);
        socket.end();
    });

    socket.pipe(server_socket);
    server_socket.pipe(socket);
}

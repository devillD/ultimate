import http from 'node:http';
import { v1, v1socket, v1wsmeta, v1wsnewmeta } from './V1.mjs';
import { Response } from './Response.mjs';

/**
 * Bare Server request dispatcher.
 * Routes HTTP and WebSocket requests for the Ultraviolet rewrite proxy.
 */
export default class Server {
    prefix = '/';
    fof = this.json(404, { message: 'Not found.' });
    maintainer = undefined;
    project = {
        name: 'TOMPHTTP NodeJS Bare Server',
        repository: 'https://github.com/tomphttp/bare-server-node',
    };
    log_error = false;
    activeWebSockets = 0;
    maxWebSockets = Number(process.env.MAX_CONCURRENT_WEBSOCKETS) || 30;

    constructor(directory, log_error, maintainer) {
        if (typeof log_error === 'boolean') {
            this.log_error = log_error;
        }

        if (typeof maintainer === 'object' && maintainer !== null) {
            this.maintainer = maintainer;
        }

        if (typeof directory !== 'string') {
            throw new Error('Directory must be specified.');
        }

        if (!directory.startsWith('/') || !directory.endsWith('/')) {
            throw new RangeError('Directory must start and end with /');
        }

        this.directory = directory;
    }

    error(...args) {
        if (this.log_error) {
            console.error('[Bare Server Error]', ...args);
        }
    }

    json(status, json) {
        const send = Buffer.from(JSON.stringify(json, null, '\t'));

        return new Response(send, status, {
            'content-type': 'application/json; charset=utf-8',
            'content-length': send.byteLength,
            'x-robots-tag': 'noindex',
            'access-control-allow-headers': '*',
            'access-control-allow-origin': '*',
            'access-control-expose-headers': '*',
            'x-bare-status': status,
            'x-bare-status-text': http.STATUS_CODES[status] || 'Error',
            'x-bare-headers': JSON.stringify({
                'content-type': 'application/json; charset=utf-8',
                'content-length': String(send.byteLength),
            }),
        });
    }

    route_request(request, response) {
        if (request.url.startsWith(this.directory)) {
            this.request(request, response);
            return true;
        }
        return false;
    }

    route_upgrade(request, socket, head) {
        if (request.url.startsWith(this.directory)) {
            this.upgrade(request, socket, head);
            return true;
        }
        return false;
    }

    get instance_info() {
        const mem = process.memoryUsage();
        return {
            versions: ['v1'],
            language: 'NodeJS',
            memoryUsage: Math.round((mem.heapUsed / 1024 / 1024) * 100) / 100,
            heapTotal: Math.round((mem.heapTotal / 1024 / 1024) * 100) / 100,
            rss: Math.round((mem.rss / 1024 / 1024) * 100) / 100,
            activeWebSockets: this.activeWebSockets,
            maintainer: this.maintainer,
            developer: this.project,
        };
    }

    async upgrade(request, socket, head) {
        const service = request.url.slice(this.directory.length - 1);

        try {
            switch (service) {
                case '/v1/':
                    await v1socket(this, request, socket, head);
                    break;
                default:
                    socket.end();
                    break;
            }
        } catch (err) {
            this.error(err);
            socket.end();
        }
    }

    async request(server_request, server_response) {
        const service = server_request.url.slice(this.directory.length - 1);
        let response;

        try {
            switch (service) {
                case '/':
                    if (server_request.method !== 'GET') {
                        response = this.json(405, { message: 'This route only accepts the GET method.' });
                    } else {
                        response = this.json(200, this.instance_info);
                    }
                    break;
                case '/v1/':
                    response = await v1(this, server_request);
                    break;
                case '/v1/ws-meta':
                    response = await v1wsmeta(this, server_request);
                    break;
                case '/v1/ws-new-meta':
                    response = await v1wsnewmeta(this, server_request);
                    break;
                default:
                    response = this.fof;
            }
        } catch (err) {
            this.error(err);

            if (err instanceof Error) {
                response = this.json(500, {
                    code: 'UNKNOWN',
                    id: `error.${err.name}`,
                    message: err.message,
                });
            } else {
                response = this.json(500, {
                    code: 'UNKNOWN',
                    id: 'error.Exception',
                    message: String(err),
                });
            }
        }

        if (!(response instanceof Response)) {
            this.error('Response to', server_request.url, 'was not a response.');
            response = this.fof;
        }

        response.send(server_response);
    }
}
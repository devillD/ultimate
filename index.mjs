import Server from './bare/Server.mjs';
import http from 'node:http';
import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { RateLimiter, AdminController } from './bare/Security.mjs';

// Paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STATIC_DIR = path.join(__dirname, 'static');

// Configuration
const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || '::';
const MAX_CONCURRENT_SESSIONS = Number(process.env.MAX_CONCURRENT_SESSIONS) || 30;
const HEAP_ALERT_THRESHOLD_MB = 160;

// Subsystems
const bare = new Server('/bare/', true);
const rateLimiter = new RateLimiter(Number(process.env.RATE_LIMIT_PER_MINUTE) || 600);
const adminController = new AdminController(process.env.ADMIN_SECRET || '');

// Global session tracking
let activeSessions = 0;
let isShuttingDown = false;
const activeSockets = new Set();

// MIME Types Map
const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.mjs': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.txt': 'text/plain; charset=utf-8',
    '.wasm': 'application/wasm',
};

/**
 * Extracts the real client IP address from request headers or socket.
 * @param {http.IncomingMessage} req
 * @returns {string} Client IP address
 */
function getClientIp(req) {
    const flyIp = req.headers['fly-client-ip'];
    if (flyIp && typeof flyIp === 'string') return flyIp.trim();

    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded && typeof forwarded === 'string') {
        return forwarded.split(',')[0].trim();
    }

    return req.socket.remoteAddress || '127.0.0.1';
}

/**
 * Sets Content-Security-Policy and security headers on the outer proxy shell.
 * @param {http.ServerResponse} res
 */
function applySecurityHeaders(res) {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; frame-src 'self' blob:; connect-src 'self' wss: ws: https:; img-src 'self' data: blob: https:; object-src 'none'; base-uri 'self';"
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

/**
 * Streams a static file from the /static directory with path-traversal protection and caching.
 *
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 */
async function serveStaticFile(req, res) {
    try {
        let reqPath = decodeURIComponent(req.url.split('?')[0]);
        if (reqPath === '/' || reqPath === '') {
            reqPath = '/index.html';
        }

        // Prevent directory traversal attacks
        const safePath = path.normalize(path.join(STATIC_DIR, reqPath));
        if (!safePath.startsWith(STATIC_DIR)) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            return res.end('Forbidden');
        }

        let stat;
        try {
            stat = await fs.stat(safePath);
            if (stat.isDirectory()) {
                const indexPath = path.join(safePath, 'index.html');
                stat = await fs.stat(indexPath);
            }
        } catch {
            // Fallback to /index.html for client-side routing
            const fallbackPath = path.join(STATIC_DIR, 'index.html');
            const fallbackStat = await fs.stat(fallbackPath);
            applySecurityHeaders(res);
            res.writeHead(200, {
                'Content-Type': 'text/html; charset=utf-8',
                'Content-Length': fallbackStat.size,
                'Cache-Control': 'no-cache, must-revalidate',
            });
            return createReadStream(fallbackPath).pipe(res);
        }

        const ext = path.extname(safePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';
        const isHtml = ext === '.html';

        applySecurityHeaders(res);
        res.writeHead(200, {
            'Content-Type': contentType,
            'Content-Length': stat.size,
            'Cache-Control': isHtml ? 'no-cache, must-revalidate' : 'public, max-age=3600',
        });

        createReadStream(safePath).pipe(res);
    } catch (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Internal Server Error: ' + err.message);
    }
}

/**
 * Handles the health check / status endpoint.
 * Returns HTTP 200 when healthy, or HTTP 503 if memory/concurrency is critical.
 *
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 */
function handleHealthCheck(req, res) {
    const mem = process.memoryUsage();
    const heapUsedMB = Math.round((mem.heapUsed / 1024 / 1024) * 100) / 100;
    const heapTotalMB = Math.round((mem.heapTotal / 1024 / 1024) * 100) / 100;
    const rssMB = Math.round((mem.rss / 1024 / 1024) * 100) / 100;

    const isOverloaded = isShuttingDown || heapUsedMB >= HEAP_ALERT_THRESHOLD_MB || activeSessions > MAX_CONCURRENT_SESSIONS;
    const statusCode = isOverloaded ? 503 : 200;

    const body = JSON.stringify(
        {
            status: isOverloaded ? 'overloaded' : 'ok',
            activeSessions,
            activeWebSockets: bare.activeWebSockets,
            maxSessions: MAX_CONCURRENT_SESSIONS,
            heapUsedMB,
            heapTotalMB,
            rssMB,
            uptimeSeconds: Math.round(process.uptime()),
            shuttingDown: isShuttingDown,
        },
        null,
        2
    );

    res.writeHead(statusCode, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
        'Cache-Control': 'no-store, no-cache, must-revalidate',
    });
    res.end(body);
}

/**
 * Handles auth-gated admin actions via POST /api/admin/action.
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 */
async function handleAdminAction(req, res) {
    if (req.method !== 'POST') {
        res.writeHead(405, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Method not allowed. Use POST.' }));
    }

    const auth = req.headers.authorization;
    if (!adminController.isAuthorized(auth)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Unauthorized: Invalid or missing admin secret token.' }));
    }

    let bodyText = '';
    req.on('data', (chunk) => {
        bodyText += chunk;
        if (bodyText.length > 10000) req.destroy();
    });

    req.on('end', () => {
        try {
            const data = JSON.parse(bodyText || '{}');
            const { action, ip } = data;

            switch (action) {
                case 'block_ip':
                    if (!ip) throw new Error('Missing IP address to block.');
                    adminController.blockIP(ip);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ success: true, message: `IP ${ip} blocked.` }));

                case 'unblock_ip':
                    if (!ip) throw new Error('Missing IP address to unblock.');
                    adminController.unblockIP(ip);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ success: true, message: `IP ${ip} unblocked.` }));

                case 'kill_sessions':
                    let killedCount = 0;
                    for (const socket of activeSockets) {
                        socket.destroy();
                        killedCount += 1;
                    }
                    activeSessions = 0;
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ success: true, message: `Terminated ${killedCount} active connections.` }));

                case 'get_metrics':
                    const mem = process.memoryUsage();
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    return res.end(
                        JSON.stringify({
                            activeSessions,
                            activeWebSockets: bare.activeWebSockets,
                            maxSessions: MAX_CONCURRENT_SESSIONS,
                            blockedIPs: Array.from(adminController.blockedIPs),
                            heapUsedMB: Math.round((mem.heapUsed / 1024 / 1024) * 100) / 100,
                            rssMB: Math.round((mem.rss / 1024 / 1024) * 100) / 100,
                        })
                    );

                default:
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ error: `Unknown action: '${action}'` }));
            }
        } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: err.message }));
        }
    });
}

// Create HTTP Server
const server = http.createServer((request, response) => {
    // 1. Graceful shutdown rejection
    if (isShuttingDown) {
        response.writeHead(503, {
            'Content-Type': 'text/plain; charset=utf-8',
            'Connection': 'close',
            'Retry-After': '5',
        });
        return response.end('Server is shutting down. Please retry shortly.');
    }

    const clientIp = getClientIp(request);

    // 2. IP Blocklist check
    if (adminController.isBlocked(clientIp)) {
        response.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
        return response.end('Access forbidden: Your IP address has been blocked by the administrator.');
    }

    // 3. Health & Status Endpoints
    if (request.url === '/healthz' || request.url === '/status') {
        return handleHealthCheck(request, response);
    }

    // 4. Admin API Endpoint
    if (request.url === '/api/admin/action') {
        return handleAdminAction(request, response);
    }

    // 5. Rate Limiter check (exempt localhost loopback during local testing)
    const isLocalhost = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1';
    if (!isLocalhost) {
        const rate = rateLimiter.check(clientIp);
        if (!rate.allowed) {
            const sendJson = Buffer.from(
                JSON.stringify({
                    error: 'Too Many Requests',
                    message: `Rate limit exceeded. Please retry after ${rate.retryAfter} seconds.`,
                })
            );
            const headers = {
                'Content-Type': 'application/json; charset=utf-8',
                'Content-Length': sendJson.byteLength,
                'Retry-After': String(rate.retryAfter),
                'x-bare-status': '429',
                'x-bare-status-text': 'Too Many Requests',
                'x-bare-headers': JSON.stringify({
                    'content-type': 'application/json; charset=utf-8',
                    'retry-after': String(rate.retryAfter),
                }),
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Expose-Headers': '*',
            };
            response.writeHead(429, headers);
            return response.end(sendJson);
        }
    }

    // 6. Session tracking for proxy routes (/bare/ or Ultraviolet prefix /-/)
    const isProxyRoute = request.url.startsWith('/bare/') || request.url.startsWith('/-/');

    if (isProxyRoute) {
        if (activeSessions >= MAX_CONCURRENT_SESSIONS) {
            response.writeHead(503, {
                'Content-Type': 'application/json; charset=utf-8',
                'Retry-After': '5',
            });
            return response.end(
                JSON.stringify({
                    error: 'Server Busy',
                    message: `The proxy is currently at maximum concurrent session capacity (${MAX_CONCURRENT_SESSIONS}/${MAX_CONCURRENT_SESSIONS}). Please try again in a moment.`,
                })
            );
        }

        // Increment active session counter
        activeSessions += 1;
        let sessionClosed = false;

        const onSessionEnd = () => {
            if (!sessionClosed) {
                sessionClosed = true;
                activeSessions = Math.max(0, activeSessions - 1);
            }
        };

        response.once('finish', onSessionEnd);
        response.once('close', onSessionEnd);
    }

    // 7. Route to Bare Server
    if (bare.route_request(request, response)) {
        return true;
    }

    // 8. Serve static files (Landing page, UV assets, Browser UI) with native zero-dependency streaming
    serveStaticFile(request, response);
});

// Socket Tracking and Timeout Tuning
server.setTimeout(30000); // 30s socket idle timeout
server.keepAliveTimeout = 5000; // 5s keep-alive timeout
server.headersTimeout = 10000; // 10s header reception timeout

server.on('connection', (socket) => {
    activeSockets.add(socket);
    socket.once('close', () => {
        activeSockets.delete(socket);
    });
});

server.on('upgrade', (req, socket, head) => {
    if (isShuttingDown) {
        socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
        socket.end();
        return;
    }

    const clientIp = getClientIp(req);
    if (adminController.isBlocked(clientIp)) {
        socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
        socket.end();
        return;
    }

    if (bare.route_upgrade(req, socket, head)) {
        return;
    }
    socket.end();
});

// Graceful Shutdown handler
function gracefulShutdown(signal) {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.log(`\n[Server] Received ${signal}. Starting graceful shutdown...`);

    // Stop accepting new connections
    server.close(() => {
        console.log('[Server] HTTP server closed cleanly.');
        process.exit(0);
    });

    // Force close after 10s if connections remain stuck
    const forceTimer = setTimeout(() => {
        console.warn('[Server] Forcing shutdown after 10s timeout.');
        for (const socket of activeSockets) {
            socket.destroy();
        }
        process.exit(0);
    }, 10000);

    if (forceTimer.unref) {
        forceTimer.unref();
    }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server with dual-stack binding
server.listen(PORT, HOST, () => {
    console.log(`[Server] Web Proxy running on http://[${HOST}]:${PORT} (Max concurrent sessions: ${MAX_CONCURRENT_SESSIONS})`);
});

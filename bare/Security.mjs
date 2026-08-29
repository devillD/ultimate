import dns from 'node:dns/promises';
import net from 'node:net';

/**
 * Checks whether an IP address belongs to a private, loopback, link-local,
 * cloud metadata, or reserved IP range.
 * 
 * Jargon definition: "SSRF" (Server-Side Request Forgery) is a security vulnerability
 * where an attacker tricks a server into making network requests to internal systems,
 * private networks, or cloud metadata endpoints that should never be publicly accessible.
 *
 * @param {string} ip - The IPv4 or IPv6 address string to test.
 * @returns {boolean} True if the IP is private or blocked; false if it is safe/public.
 */
export function isPrivateOrBlockedIP(ip) {
    if (!ip || typeof ip !== 'string') return true;

    // Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
    if (ip.startsWith('::ffff:')) {
        ip = ip.slice(7);
    }

    const version = net.isIP(ip);
    if (!version) return true; // Invalid IP format is treated as unsafe

    if (version === 4) {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return true;

        const [b0, b1, b2, b3] = parts;

        // 0.0.0.0/8 (Current network)
        if (b0 === 0) return true;

        // 10.0.0.0/8 (Private network RFC 1918)
        if (b0 === 10) return true;

        // 100.64.0.0/10 (Carrier-grade NAT RFC 6598)
        if (b0 === 100 && (b1 >= 64 && b1 <= 127)) return true;

        // 127.0.0.0/8 (Loopback / localhost)
        if (b0 === 127) return true;

        // 169.254.0.0/16 (Link-local / Cloud metadata e.g., 169.254.169.254)
        if (b0 === 169 && b1 === 254) return true;

        // 172.16.0.0/12 (Private network RFC 1918)
        if (b0 === 172 && (b1 >= 16 && b1 <= 31)) return true;

        // 192.0.0.0/24 (IETF Protocol Assignments)
        if (b0 === 192 && b1 === 0 && b2 === 0) return true;

        // 192.0.2.0/24 (TEST-NET-1)
        if (b0 === 192 && b1 === 0 && b2 === 2) return true;

        // 192.88.99.0/24 (6to4 Relay Anycast)
        if (b0 === 192 && b1 === 88 && b2 === 99) return true;

        // 192.168.0.0/16 (Private network RFC 1918)
        if (b0 === 192 && b1 === 168) return true;

        // 198.18.0.0/15 (Benchmarking)
        if (b0 === 198 && (b1 === 18 || b1 === 19)) return true;

        // 198.51.100.0/24 (TEST-NET-2)
        if (b0 === 198 && b1 === 51 && b2 === 100) return true;

        // 203.0.113.0/24 (TEST-NET-3)
        if (b0 === 203 && b1 === 0 && b2 === 113) return true;

        // 224.0.0.0/4 (Multicast)
        if (b0 >= 224 && b0 <= 239) return true;

        // 240.0.0.0/4 (Reserved / Future use / Broadcast)
        if (b0 >= 240) return true;

        // 255.255.255.255 (Broadcast)
        if (b0 === 255 && b1 === 255 && b2 === 255 && b3 === 255) return true;

        return false;
    }

    if (version === 6) {
        const lower = ip.toLowerCase();

        // ::1 (Loopback)
        if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;

        // :: (Unspecified)
        if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true;

        // fc00::/7 (Unique Local Address RFC 4193)
        if (lower.startsWith('fc') || lower.startsWith('fd')) return true;

        // fe80::/10 (Link-local unicast RFC 4291)
        if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;

        // ff00::/8 (Multicast)
        if (lower.startsWith('ff')) return true;

        return false;
    }

    return true;
}

/**
 * Validates the basic structural parameters of a requested destination URL object.
 *
 * @param {Object} remote - Remote descriptor with host, port, protocol, path.
 * @returns {null|Object} Error object if invalid, or null if valid.
 */
export function validateDestinationUrl(remote) {
    if (!remote || typeof remote !== 'object') {
        return {
            code: 'INVALID_DESTINATION',
            id: 'request.destination',
            message: 'Destination object was missing or malformed.',
        };
    }

    if (remote.protocol !== 'http:' && remote.protocol !== 'https:' && remote.protocol !== 'ws:' && remote.protocol !== 'wss:') {
        return {
            code: 'FORBIDDEN_PROTOCOL',
            id: 'request.protocol',
            message: `Protocol '${remote.protocol}' is forbidden. Only HTTP, HTTPS, WS, and WSS are allowed.`,
        };
    }

    if (!remote.host || typeof remote.host !== 'string' || remote.host.trim() === '') {
        return {
            code: 'INVALID_HOST',
            id: 'request.host',
            message: 'Destination hostname was missing or empty.',
        };
    }

    const host = remote.host.toLowerCase().trim();

    // Block common internal/cloud metadata hostnames directly
    if (
        host === 'localhost' ||
        host.endsWith('.localhost') ||
        host.endsWith('.local') ||
        host.endsWith('.internal') ||
        host === 'metadata.google.internal' ||
        host === 'instance-data'
    ) {
        return {
            code: 'FORBIDDEN_HOST',
            id: 'request.host',
            message: `Access to internal host '${remote.host}' is blocked by SSRF protection.`,
        };
    }

    const port = Number(remote.port);
    if (isNaN(port) || port < 1 || port > 65535) {
        return {
            code: 'INVALID_PORT',
            id: 'request.port',
            message: `Port '${remote.port}' is out of valid range (1-65535).`,
        };
    }

    return null;
}

// In-memory DNS cache to eliminate redundant OS lookups and libuv threadpool contention
const dnsCache = new Map();
const DNS_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes TTL
const DNS_CACHE_MAX_ENTRIES = 1000;

// Periodic cleanup every 60 seconds (<100KB RAM overhead)
const dnsCleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [host, entry] of dnsCache.entries()) {
        if (now > entry.expiresAt) {
            dnsCache.delete(host);
        }
    }
}, 60 * 1000);

if (dnsCleanupTimer.unref) {
    dnsCleanupTimer.unref();
}

// Known telemetry / analytics / tracking domains that generate useless background ping loops
const TELEMETRY_HOSTS = new Set([
    'collector.github.com',
    'analytics.google.com',
    'stats.g.doubleclick.net',
    'play.google.com',
    'telemetry.github.com',
    'api.segment.io',
    'sentry.io',
    'browser.sentry-cdn.com',
    'vortex.data.microsoft.com',
    'browser.events.data.microsoft.com',
    'bat.bing.com',
    'clarity.ms',
    'c.clarity.ms',
    'analytics.tiktok.com',
    'tr.snapchat.com',
    'adservice.google.com',
]);

/**
 * Checks if a host is a known telemetry, analytics, or background tracking endpoint.
 * @param {string} host
 * @returns {boolean}
 */
export function isTelemetryHost(host) {
    if (!host || typeof host !== 'string') return false;
    const lower = host.toLowerCase().trim();
    if (TELEMETRY_HOSTS.has(lower)) return true;
    if (lower.startsWith('telemetry.') || lower.startsWith('analytics.') || lower.startsWith('collector.')) return true;
    return false;
}

/**
 * Resolves a hostname through DNS and checks all resulting IP addresses
 * against private/cloud-metadata IP ranges to prevent SSRF and DNS-rebinding attacks.
 * Uses an in-memory cache to ensure near-zero latency for repeated domain lookups.
 *
 * @param {string} hostname - The hostname or IP to resolve and verify.
 * @returns {Promise<{safe: boolean, resolvedIp?: string, error?: Object}>}
 */
export async function resolveAndValidateHost(hostname) {
    // Strip IPv6 brackets if present
    const cleanHost = hostname.replace(/^\[|\]$/g, '').trim();

    // If host is already an IP address, validate directly
    if (net.isIP(cleanHost)) {
        if (isPrivateOrBlockedIP(cleanHost)) {
            return {
                safe: false,
                error: {
                    code: 'SSRF_BLOCKED_IP',
                    id: 'request.security.ssrf',
                    message: `Target IP '${cleanHost}' is in a private or restricted network range.`,
                },
            };
        }
        return { safe: true, resolvedIp: cleanHost };
    }

    // Check fast in-memory DNS cache
    const cached = dnsCache.get(cleanHost);
    if (cached && Date.now() < cached.expiresAt) {
        return cached.result;
    }

    try {
        // Resolve all IPv4 and IPv6 addresses for the hostname
        const addresses = await dns.lookup(cleanHost, { all: true });

        if (!addresses || addresses.length === 0) {
            return {
                safe: false,
                error: {
                    code: 'DNS_RESOLUTION_FAILED',
                    id: 'request.dns',
                    message: `Could not resolve hostname '${cleanHost}'.`,
                },
            };
        }

        // Check every resolved IP address
        for (const record of addresses) {
            if (isPrivateOrBlockedIP(record.address)) {
                return {
                    safe: false,
                    error: {
                        code: 'SSRF_BLOCKED_RESOLVED_IP',
                        id: 'request.security.ssrf',
                        message: `Hostname '${cleanHost}' resolved to private/restricted IP '${record.address}'. Access blocked.`,
                    },
                };
            }
        }

        // Return the first validated IP address for safe outbound connection and cache it
        const result = { safe: true, resolvedIp: addresses[0].address };
        if (dnsCache.size < DNS_CACHE_MAX_ENTRIES) {
            dnsCache.set(cleanHost, { result, expiresAt: Date.now() + DNS_CACHE_TTL_MS });
        }
        return result;
    } catch (err) {
        return {
            safe: false,
            error: {
                code: 'DNS_LOOKUP_ERROR',
                id: 'request.dns',
                message: `DNS lookup failed for '${cleanHost}': ${err.message}`,
            },
        };
    }
}

/**
 * Strips or neutralizes 'Content-Disposition: attachment' headers to prevent
 * proxied servers from forcing file download popups.
 *
 * @param {string} disposition - Original Content-Disposition header value.
 * @returns {string} Sanitized header value (forced to 'inline' without filename).
 */
export function sanitizeContentDisposition(disposition) {
    if (!disposition || typeof disposition !== 'string') return 'inline';
    // If it contains attachment, override to inline
    if (/attachment/i.test(disposition)) {
        return 'inline';
    }
    return disposition;
}

// Configurable set of blocked binary / executable MIME types
const BLOCKED_MIME_TYPES = new Set([
    'application/x-msdownload',
    'application/x-msdos-program',
    'application/x-dosexec',
    'application/x-executable',
    'application/vnd.android.package-archive',
    'application/x-iso9660-image',
    'application/x-apple-diskimage',
    'application/x-debian-package',
    'application/x-redhat-package-manager',
]);

/**
 * Checks whether the incoming content-type represents a blocked executable or binary download.
 *
 * @param {string} contentType - The Content-Type header from the upstream response.
 * @returns {boolean} True if the content type is blocked, false otherwise.
 */
export function isBlockedMimeType(contentType) {
    if (!contentType || typeof contentType !== 'string') return false;
    const mime = contentType.split(';')[0].trim().toLowerCase();
    return BLOCKED_MIME_TYPES.has(mime);
}

/**
 * In-memory sliding window rate limiter per IP.
 * Uses a simple Map with periodic garbage collection to stay within <1MB RAM.
 */
export class RateLimiter {
    constructor(maxRequestsPerMinute = 180) {
        this.maxRequests = maxRequestsPerMinute;
        this.windowMs = 60 * 1000;
        this.clients = new Map();

        // Periodic cleanup every 60 seconds to prevent memory leak
        this.cleanupInterval = setInterval(() => {
            const now = Date.now();
            for (const [ip, data] of this.clients.entries()) {
                if (now - data.windowStart > this.windowMs) {
                    this.clients.delete(ip);
                }
            }
        }, 60 * 1000);

        if (this.cleanupInterval.unref) {
            this.cleanupInterval.unref();
        }
    }

    /**
     * Checks if an IP is within its allowed rate limit.
     * @param {string} ip - Client IP address.
     * @returns {{allowed: boolean, remaining: number, retryAfter: number}}
     */
    check(ip) {
        const now = Date.now();
        let record = this.clients.get(ip);

        if (!record || (now - record.windowStart) > this.windowMs) {
            record = { count: 1, windowStart: now };
            this.clients.set(ip, record);
            return { allowed: true, remaining: this.maxRequests - 1, retryAfter: 0 };
        }

        record.count += 1;
        if (record.count > this.maxRequests) {
            const retryAfter = Math.ceil((this.windowMs - (now - record.windowStart)) / 1000);
            return { allowed: false, remaining: 0, retryAfter: Math.max(1, retryAfter) };
        }

        return { allowed: true, remaining: this.maxRequests - record.count, retryAfter: 0 };
    }
}

/**
 * Controller for administrative actions and IP blocklisting.
 */
export class AdminController {
    constructor(adminSecret = process.env.ADMIN_SECRET || '') {
        this.adminSecret = adminSecret;
        this.blockedIPs = new Set();
    }

    /**
     * Verifies whether a given request authorization header matches the admin secret.
     * @param {string} authHeader - Authorization header value (e.g., 'Bearer <secret>').
     * @returns {boolean} True if authorized, false otherwise.
     */
    isAuthorized(authHeader) {
        if (!this.adminSecret) return false; // If no secret is configured, admin endpoint is disabled
        if (!authHeader || typeof authHeader !== 'string') return false;
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : authHeader.trim();
        return token === this.adminSecret;
    }

    /**
     * Checks if an IP is on the blocked list.
     * @param {string} ip - The IP address to test.
     * @returns {boolean} True if blocked, false otherwise.
     */
    isBlocked(ip) {
        return this.blockedIPs.has(ip);
    }

    /**
     * Adds an IP to the blocked list.
     * @param {string} ip - IP address to block.
     */
    blockIP(ip) {
        if (ip) this.blockedIPs.add(ip);
    }

    /**
     * Removes an IP from the blocked list.
     * @param {string} ip - IP address to unblock.
     */
    unblockIP(ip) {
        if (ip) this.blockedIPs.delete(ip);
    }
}

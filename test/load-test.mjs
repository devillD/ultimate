import http from 'node:http';
import { isPrivateOrBlockedIP, validateDestinationUrl, sanitizeContentDisposition, isBlockedMimeType, RateLimiter, AdminController } from '../bare/Security.mjs';

/**
 * Automated Verification & Load Test Suite
 */
async function runTests() {
    console.log('=== STARTING AUTOMATED TEST SUITE ===\n');
    let passed = 0;
    let failed = 0;

    function assert(condition, message) {
        if (condition) {
            console.log(`  [PASS] ${message}`);
            passed++;
        } else {
            console.error(`  [FAIL] ${message}`);
            failed++;
        }
    }

    // 1. SSRF Unit Tests
    console.log('[Test Suite 1] SSRF & Private IP Detection:');
    assert(isPrivateOrBlockedIP('127.0.0.1'), 'Blocks 127.0.0.1 loopback');
    assert(isPrivateOrBlockedIP('127.0.1.5'), 'Blocks 127.0.0.0/8 subnet');
    assert(isPrivateOrBlockedIP('10.0.0.1'), 'Blocks 10.0.0.0/8 private IP');
    assert(isPrivateOrBlockedIP('172.16.5.10'), 'Blocks 172.16.0.0/12 private IP');
    assert(isPrivateOrBlockedIP('192.168.1.1'), 'Blocks 192.168.0.0/16 private IP');
    assert(isPrivateOrBlockedIP('169.254.169.254'), 'Blocks AWS/GCP/Azure cloud metadata endpoint 169.254.169.254');
    assert(isPrivateOrBlockedIP('169.254.1.1'), 'Blocks 169.254.0.0/16 link-local');
    assert(isPrivateOrBlockedIP('0.0.0.0'), 'Blocks 0.0.0.0/8');
    assert(isPrivateOrBlockedIP('100.64.0.1'), 'Blocks 100.64.0.0/10 CGNAT');
    assert(isPrivateOrBlockedIP('::1'), 'Blocks IPv6 loopback ::1');
    assert(isPrivateOrBlockedIP('fc00::1'), 'Blocks IPv6 unique local fc00::/7');
    assert(isPrivateOrBlockedIP('fe80::1'), 'Blocks IPv6 link-local fe80::/10');
    assert(isPrivateOrBlockedIP('::ffff:127.0.0.1'), 'Blocks IPv4-mapped IPv6 loopback');
    assert(isPrivateOrBlockedIP('::ffff:169.254.169.254'), 'Blocks IPv4-mapped IPv6 cloud metadata');
    assert(!isPrivateOrBlockedIP('8.8.8.8'), 'Allows public IP 8.8.8.8 (Google DNS)');
    assert(!isPrivateOrBlockedIP('1.1.1.1'), 'Allows public IP 1.1.1.1 (Cloudflare DNS)');
    assert(!isPrivateOrBlockedIP('142.250.190.46'), 'Allows public IP (google.com)');

    // 2. Destination URL Validation Tests
    console.log('\n[Test Suite 2] Destination URL Validation:');
    assert(validateDestinationUrl({ protocol: 'http:', host: 'example.com', port: 80, path: '/' }) === null, 'Allows standard HTTP destination');
    assert(validateDestinationUrl({ protocol: 'https:', host: 'example.com', port: 443, path: '/' }) === null, 'Allows standard HTTPS destination');
    assert(validateDestinationUrl({ protocol: 'file:', host: 'etc', port: 80, path: '/passwd' }) !== null, 'Rejects file:// protocol');
    assert(validateDestinationUrl({ protocol: 'gopher:', host: 'example.com', port: 70, path: '/' }) !== null, 'Rejects gopher:// protocol');
    assert(validateDestinationUrl({ protocol: 'http:', host: 'localhost', port: 80, path: '/' }) !== null, 'Rejects localhost destination hostname');
    assert(validateDestinationUrl({ protocol: 'http:', host: 'metadata.google.internal', port: 80, path: '/' }) !== null, 'Rejects metadata.google.internal');

    // 3. Download Sanitization & Blocking Tests
    console.log('\n[Test Suite 3] Download Header Sanitization & MIME Blocking:');
    assert(sanitizeContentDisposition('attachment; filename="malicious.exe"') === 'inline', 'Strips attachment and filename from Content-Disposition');
    assert(sanitizeContentDisposition('inline; filename="preview.pdf"') === 'inline; filename="preview.pdf"', 'Preserves inline disposition');
    assert(isBlockedMimeType('application/x-msdownload'), 'Blocks Windows executable MIME type');
    assert(isBlockedMimeType('application/x-dosexec'), 'Blocks DOS/Windows executable MIME type');
    assert(isBlockedMimeType('application/vnd.android.package-archive'), 'Blocks Android APK download');
    assert(!isBlockedMimeType('text/html; charset=utf-8'), 'Allows HTML MIME type');
    assert(!isBlockedMimeType('application/json'), 'Allows JSON MIME type');
    assert(!isBlockedMimeType('video/mp4'), 'Allows streaming video/mp4 MIME type');

    // 4. Rate Limiter Tests
    console.log('\n[Test Suite 4] Rate Limiter:');
    const limiter = new RateLimiter(5); // 5 req limit for testing
    for (let i = 1; i <= 5; i++) {
        assert(limiter.check('1.2.3.4').allowed === true, `Request #${i} within limit allowed`);
    }
    const rateExceeded = limiter.check('1.2.3.4');
    assert(rateExceeded.allowed === false && rateExceeded.retryAfter > 0, 'Request #6 triggers rate limit (429)');

    // 5. Admin Controller Tests
    console.log('\n[Test Suite 5] Admin Abuse Controls:');
    const admin = new AdminController('my_secret_token');
    assert(admin.isAuthorized('Bearer my_secret_token'), 'Authorizes valid admin token');
    assert(!admin.isAuthorized('Bearer wrong_token'), 'Rejects invalid admin token');
    assert(!admin.isBlocked('5.6.7.8'), 'IP initially not blocked');
    admin.blockIP('5.6.7.8');
    assert(admin.isBlocked('5.6.7.8'), 'IP successfully blocked after blockIP');
    admin.unblockIP('5.6.7.8');
    assert(!admin.isBlocked('5.6.7.8'), 'IP successfully unblocked after unblockIP');

    console.log(`\n=== TEST SUMMARY: ${passed} PASSED, ${failed} FAILED ===`);
    if (failed > 0) {
        process.exit(1);
    }
}

runTests();

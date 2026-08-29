import http from 'node:http';
import { spawn } from 'node:child_process';

/**
 * End-to-End Server Integration Test
 */
async function runE2E() {
    console.log('=== STARTING END-TO-END SERVER INTEGRATION TEST ===\n');

    const serverProcess = spawn('node', ['index.js'], {
        env: {
            ...process.env,
            PORT: '8999',
            HOST: '127.0.0.1',
            MAX_CONCURRENT_SESSIONS: '5',
            ADMIN_SECRET: 'super_secret_admin_token',
        },
        stdio: 'inherit',
    });

    // Wait 1.5s for server to start
    await new Promise((res) => setTimeout(res, 1500));

    function makeRequest(path, options = {}, bodyData = null) {
        return new Promise((resolve, reject) => {
            const req = http.request(
                {
                    hostname: '127.0.0.1',
                    port: 8999,
                    path,
                    method: options.method || 'GET',
                    headers: options.headers || {},
                },
                (res) => {
                    let data = '';
                    res.on('data', (c) => (data += c));
                    res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: data }));
                }
            );
            req.on('error', reject);
            if (bodyData) req.write(bodyData);
            req.end();
        });
    }

    try {
        // 1. Health check test
        console.log('[E2E 1] Testing /healthz endpoint:');
        const healthRes = await makeRequest('/healthz');
        console.log(`  Status code: ${healthRes.statusCode}`);
        const health = JSON.parse(healthRes.body);
        console.log(`  Health status: ${health.status}, Active sessions: ${health.activeSessions}, Max: ${health.maxSessions}, Heap: ${health.heapUsedMB}MB`);
        if (healthRes.statusCode !== 200 || health.status !== 'ok') {
            throw new Error('Health check failed');
        }

        // 2. Static landing page test
        console.log('\n[E2E 2] Testing Landing Page & CSP:');
        const landingRes = await makeRequest('/');
        console.log(`  Status code: ${landingRes.statusCode}`);
        console.log(`  CSP header: ${landingRes.headers['content-security-policy']?.slice(0, 45)}...`);
        if (!landingRes.body.includes('Web Proxy') || !landingRes.headers['content-security-policy']) {
            throw new Error('Landing page or CSP header missing');
        }

        // 3. Admin API action test
        console.log('\n[E2E 3] Testing Admin Action (Block IP):');
        const adminRes = await makeRequest(
            '/api/admin/action',
            {
                method: 'POST',
                headers: {
                    Authorization: 'Bearer super_secret_admin_token',
                    'Content-Type': 'application/json',
                },
            },
            JSON.stringify({ action: 'block_ip', ip: '10.99.88.77' })
        );
        console.log(`  Status code: ${adminRes.statusCode}, Body: ${adminRes.body}`);
        const adminData = JSON.parse(adminRes.body);
        if (adminRes.statusCode !== 200 || !adminData.success) {
            throw new Error('Admin block_ip failed');
        }

        // 4. Bare server SSRF protection test
        console.log('\n[E2E 4] Testing Bare Proxy SSRF protection (requesting localhost metadata):');
        const ssrfRes = await makeRequest('/bare/v1/', {
            headers: {
                'x-bare-host': '169.254.169.254',
                'x-bare-port': '80',
                'x-bare-protocol': 'http:',
                'x-bare-path': '/latest/meta-data/',
                'x-bare-headers': '{}',
                'x-bare-forward-headers': '[]',
            },
        });
        console.log(`  Status code: ${ssrfRes.statusCode}, Body: ${ssrfRes.body}`);
        if (ssrfRes.statusCode !== 403) {
            throw new Error('SSRF request was not blocked with 403');
        }

        console.log('\n=== ALL E2E INTEGRATION TESTS PASSED ===');
    } finally {
        serverProcess.kill('SIGTERM');
        await new Promise((res) => setTimeout(res, 500));
    }
}

runE2E().catch((err) => {
    console.error('E2E Test Failed:', err);
    process.exit(1);
});

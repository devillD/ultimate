import http from 'node:http';

async function testBareFetch() {
    console.log('Testing /bare/v1/ request to https://example.com/ ...');

    const headers = {
        'x-bare-host': 'example.com',
        'x-bare-port': '443',
        'x-bare-protocol': 'https:',
        'x-bare-path': '/',
        'x-bare-headers': JSON.stringify({
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-encoding': 'gzip, deflate, br',
        }),
        'x-bare-forward-headers': JSON.stringify(['user-agent', 'accept', 'accept-encoding']),
    };

    const req = http.request(
        {
            hostname: '127.0.0.1',
            port: 8080,
            path: '/bare/v1/',
            method: 'GET',
            headers,
        },
        (res) => {
            console.log('Bare response status:', res.statusCode);
            console.log('Bare response headers:', res.headers);
            let body = '';
            res.on('data', (c) => (body += c));
            res.on('end', () => {
                console.log('Body length:', body.length);
                console.log('Body preview:', body.slice(0, 300));
            });
        }
    );

    req.on('error', console.error);
    req.end();
}

testBareFetch();

const http = require('node:http');

function createLabServer() {
  return http.createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    if (url.pathname === '/xss') return response.end(`<p>${url.searchParams.get('q') || ''}</p>`);
    if (url.pathname === '/sqli') return response.end(/OR '1'='1/i.test(url.searchParams.get('q') || '') ? 'row:1\nrow:2' : 'row:1');
    if (url.pathname === '/cors') { response.setHeader('access-control-allow-origin', request.headers.origin || '*'); response.setHeader('access-control-allow-credentials', 'true'); return response.end('{"lab":true}'); }
    if (url.pathname === '/redirect') { response.statusCode = 302; response.setHeader('location', url.searchParams.get('next') || '/'); return response.end(); }
    response.statusCode = 404; return response.end('not found');
  });
}

if (require.main === module) createLabServer().listen(Number(process.env.LAB_PORT || 4180), '127.0.0.1');
module.exports = { createLabServer };

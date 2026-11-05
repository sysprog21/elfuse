'use strict';
// elfuse exposes guest loopback sockets on the host. Port 0 avoids collisions.

const http = require('http');

const server = http.createServer((req, res) => {
  if (req.url === '/quit') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('bye\n');
    server.close(() => process.exit(0));
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('elfuse-node-server-ok\n');
});

server.on('error', (e) => {
  console.error('server error: ' + e.message);
  process.exit(1);
});

server.listen(0, '127.0.0.1', () => {
  console.log('PORT=' + server.address().port);
});

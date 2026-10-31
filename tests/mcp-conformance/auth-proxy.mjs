import http from 'node:http';

const target = new URL(process.env.TARGET_URL ?? 'http://127.0.0.1:18089');
const listen = new URL(process.env.LISTEN_URL ?? 'http://127.0.0.1:18092');
const accessToken = process.env.ACCESS_TOKEN;
if (!accessToken) throw new Error('ACCESS_TOKEN is required');

const server = http.createServer((req, res) => {
  const upstream = http.request(
    {
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      method: req.method,
      path: req.url,
      headers: { ...req.headers, authorization: `Bearer ${accessToken}` },
    },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
      upstreamRes.pipe(res);
    },
  );
  upstream.on('error', () => {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('conformance upstream unavailable');
  });
  req.pipe(upstream);
});
server.on('clientError', (_error, socket) => socket.destroy());
server.listen(Number(listen.port), listen.hostname, () => {
  console.log(`conformance auth proxy listening on ${listen.origin}`);
});
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}

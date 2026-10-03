import { createServer as createHttpServer } from 'node:http';
import { Readable } from 'node:stream';
import { createServer as createViteServer } from 'vite';
try { process.loadEnvFile('.env'); } catch { /* Local OAuth settings are optional until configured. */ }
const { default: apiHandler } = await import('../api/[...route].js');

const api = createHttpServer(async (incoming, outgoing) => {
  try {
    const headers = new Headers();
    for (const name of ['accept', 'content-type', 'cookie', 'origin']) {
      const value = incoming.headers[name];
      if (value) headers.set(name, value);
    }
    const method = incoming.method || 'GET';
    const request = new Request(new URL(incoming.url || '/', process.env.APP_ORIGIN || 'http://localhost:5173'), {
      method, headers,
      ...(method === 'GET' || method === 'HEAD' ? {} : { body: Readable.toWeb(incoming), duplex: 'half' }),
    });
    const result = await apiHandler.fetch(request);
    outgoing.statusCode = result.status;
    for (const [name, value] of result.headers) if (name.toLowerCase() !== 'set-cookie') outgoing.setHeader(name, value);
    if (result.headers.getSetCookie) outgoing.setHeader('Set-Cookie', result.headers.getSetCookie());
    else if (result.headers.get('set-cookie')) outgoing.setHeader('Set-Cookie', result.headers.get('set-cookie'));
    outgoing.end(Buffer.from(await result.arrayBuffer()));
  } catch (error) {
    console.error(error);
    outgoing.writeHead(500, { 'Content-Type': 'application/json' });
    outgoing.end(JSON.stringify({ error: 'Error local del servidor.' }));
  }
});

const vite = await createViteServer({
  configFile: './vite.config.js',
  server: { host: '0.0.0.0', proxy: { '/api': { target: 'http://127.0.0.1:8787', changeOrigin: false } } },
});
await vite.listen();
process.env.APP_ORIGIN = new URL(vite.resolvedUrls.local[0]).origin;
api.listen(8787, '127.0.0.1');
vite.printUrls();

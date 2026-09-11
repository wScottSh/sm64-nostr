/*
 * serve-debug.mjs -- one-command HTTPS spin-up for debug.html so a phone on
 * the same LAN can open it and use its camera. Phone camera access
 * (getUserMedia) requires a secure context, and only localhost is exempt --
 * a LAN IP is not -- so this serves over HTTPS with a self-signed cert
 * (generated once into ./.debug-certs/ via openssl, gitignored). Dependency-
 * free: Node core + a system `openssl` only.
 *
 *   node reader/serve-debug.mjs            # port 8443
 *   node reader/serve-debug.mjs 9000       # custom port
 *
 * Prints every LAN URL to open. The phone will warn about the self-signed
 * cert -- tap Advanced -> proceed. Set the page's "Frame host" field to the
 * host baked into your cabinet's frame URLs (e.g. SM64NOSTR.PAGES.DEV); the
 * served-from LAN IP won't match it, but real frames are still logged either
 * way -- they just won't reassemble until the host matches.
 */
import { createServer } from 'node:https';
import { readFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { extname, join, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { networkInterfaces } from 'node:os';

const ROOT = dirname(fileURLToPath(import.meta.url)); // the reader/ dir
const PORT = Number(process.argv[2] || process.env.PORT || 8443);
const CERT_DIR = join(ROOT, '.debug-certs');
const CERT = join(CERT_DIR, 'cert.pem');
const KEY = join(CERT_DIR, 'key.pem');

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.map': 'application/json',
};

function lanIPv4s() {
  const out = [];
  for (const addrs of Object.values(networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === 'IPv4' && !a.internal) out.push(a.address);
    }
  }
  return out;
}

async function ensureCert() {
  if (existsSync(CERT) && existsSync(KEY)) return;
  await mkdir(CERT_DIR, { recursive: true });
  const ips = lanIPv4s();
  const san = ['IP:127.0.0.1', 'DNS:localhost', ...ips.map((ip) => `IP:${ip}`)].join(',');
  const cn = ips[0] || 'localhost';
  console.log(`Generating self-signed cert (CN=${cn}, SAN=${san}) ...`);
  const r = spawnSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', KEY, '-out', CERT, '-days', '365',
    '-subj', `/CN=${cn}`, '-addext', `subjectAltName=${san}`,
  ], { stdio: 'inherit' });
  if (r.status !== 0) {
    console.error('\nopenssl failed (is it installed and on PATH?). Cannot serve HTTPS without a cert.');
    process.exit(1);
  }
}

if (!existsSync(join(ROOT, 'generated', 'transport_contract.js'))) {
  console.error('Missing generated/transport_contract.js -- run `npm run build` in reader/ first '
    + '(python3 tools/gen_transport_contract_js.py --out generated/transport_contract.js).');
  process.exit(1);
}

await ensureCert();

const opts = { key: await readFile(KEY), cert: await readFile(CERT) };
createServer(opts, async (req, res) => {
  try {
    let p = decodeURIComponent(req.url.split('?')[0]);
    if (p === '/') p = '/debug.html';
    const filePath = normalize(join(ROOT, p));
    if (!filePath.startsWith(normalize(ROOT))) { res.writeHead(403); res.end('forbidden'); return; }
    if (!existsSync(filePath)) { res.writeHead(404); res.end('not found: ' + p); return; }
    res.writeHead(200, { 'content-type': TYPES[extname(filePath)] || 'application/octet-stream' });
    res.end(await readFile(filePath));
  } catch (e) {
    res.writeHead(500); res.end(String(e));
  }
}).listen(PORT, '0.0.0.0', () => {
  const urls = lanIPv4s();
  console.log('\ndebug.html is live. Open on your phone (same network):\n');
  for (const ip of urls) console.log(`  https://${ip}:${PORT}/debug.html`);
  console.log(`  https://localhost:${PORT}/debug.html   (this machine)\n`);
  console.log('Accept the self-signed-cert warning on the phone, then tap Start camera.');
});

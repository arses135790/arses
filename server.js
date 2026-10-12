'use strict';
// Arses (آرسس) - VLESS/Trojan over WebSocket gateway + admin dashboard. No dependencies.
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { Store, GB } = require('./src/store');
const { Auth } = require('./src/auth');
const { Gateway } = require('./src/relay');
const { toSvg } = require('./src/qr');
const socks = require('./src/socks');

const PORT = Number(process.env.PORT) || 8000;
const store = new Store();
const auth = new Auth(store);
const gw = new Gateway(store);
const startedAt = Date.now();
const PUB = path.join(__dirname, 'public');
const settings = store.data.settings;
if (process.env.VLESS_PATH) settings.vlessPath = process.env.VLESS_PATH;
if (process.env.TROJAN_PATH) settings.trojanPath = process.env.TROJAN_PATH;
if (process.env.CONFIG_ADDRESS && !settings.configAddress) settings.configAddress = process.env.CONFIG_ADDRESS;
// Default UAE exit = the VIP AE proxy from the Zeus repo (proxy_vip/AE.txt). Change/remove it in the panel; verify with "تست کشور خروجی".
if (settings.upstreamProxy === undefined) settings.upstreamProxy = process.env.UPSTREAM_PROXY !== undefined ? process.env.UPSTREAM_PROXY : "socks5://zfdsvi6l:dl7o17z4ml9q@ua.day1404.dpdns.org:11359";
if (settings.configLabel === undefined) settings.configLabel = '🇦🇪 امارات';
const ADDR_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)$/;

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
const SEC = {
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
};

const clientIp = (req) => (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
const isHttps = (req) => req.headers['x-forwarded-proto'] === 'https';

function send(res, code, body, type = 'application/json; charset=utf-8', extra = {}) {
  res.writeHead(code, { 'Content-Type': type, ...SEC, ...extra });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
const json = (res, code, obj, extra) => send(res, code, JSON.stringify(obj), 'application/json; charset=utf-8', extra);

function readBody(req, limit = 65536) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {}); } catch { reject(new Error('bad json')); } });
    req.on('error', reject);
  });
}

function publicHost(req) {
  const h = process.env.PUBLIC_HOST || process.env.RAILWAY_PUBLIC_DOMAIN || req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
  return String(h).split(',')[0].trim();
}

function uris(req, l) {
  const host = publicHost(req);
  const tls = isHttps(req) || !!process.env.PUBLIC_HOST || !!process.env.RAILWAY_PUBLIC_DOMAIN;
  const hostname = host.replace(/:\d+$/, '');
  const port = tls ? 443 : (/:(\d+)$/.exec(host) || [, 80])[1];
  const sec = tls ? `security=tls&sni=${hostname}&fp=chrome&alpn=http%2F1.1` : 'security=none';
  const addr = settings.configAddress || hostname;      // UAE IP shown in the config; SNI/Host stay on the real domain
  const tag = encodeURIComponent(settings.configLabel ? `${settings.configLabel} ${l.name}` : l.name);
  const enc = encodeURIComponent;
  return {
    vless: `vless://${l.uuid}@${addr}:${port}?encryption=none&${sec}&type=ws&host=${hostname}&path=${enc(settings.vlessPath)}#${tag}`,
    trojan: `trojan://${l.uuid}@${addr}:${port}?${sec}&type=ws&host=${hostname}&path=${enc(settings.trojanPath)}#${tag}`,
  };
}

function view(l, req) {
  const used = l.up + l.down;
  return {
    id: l.id, name: l.name, enabled: l.enabled, uuid: l.uuid, createdAt: l.createdAt, expiresAt: l.expiresAt,
    quotaBytes: l.quotaBytes, up: l.up, down: l.down, used, lastSeen: l.lastSeen,
    live: gw.liveCount(l.id), status: store.blockReason(l) || 'active', ...uris(req, l),
  };
}

function num(v, min, max) { const n = Number(v); return Number.isFinite(n) && n >= min && n <= max ? n : null; }

async function api(req, res, url) {
  const p = url.pathname, m = req.method;
  if (p === '/api/health') return json(res, 200, { ok: true });

  if (p === '/api/login' && m === 'POST') {
    const ip = clientIp(req);
    if (auth.tooManyFailures(ip)) return json(res, 429, { error: 'تلاش‌های ناموفق زیاد؛ چند دقیقه بعد دوباره امتحان کنید' });
    const b = await readBody(req).catch(() => ({}));
    if (!auth.checkLogin(b.username || '', b.password || '')) { auth.recordFailure(ip); return json(res, 401, { error: 'نام کاربری یا رمز اشتباه است' }); }
    auth.clearFailures(ip);
    const cookie = `arses_sid=${auth.makeSession()}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800${isHttps(req) ? '; Secure' : ''}`;
    return json(res, 200, { ok: true }, { 'Set-Cookie': cookie });
  }
  if (p === '/api/logout' && m === 'POST') return json(res, 200, { ok: true }, { 'Set-Cookie': 'arses_sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0' });

  if (!auth.readSession(req.headers.cookie)) return json(res, 401, { error: 'auth' });
  if (m !== 'GET' && !String(req.headers['content-type'] || '').startsWith('application/json')) return json(res, 415, { error: 'json only' });

  if (p === '/api/links' && m === 'GET') return json(res, 200, store.list().sort((a, b) => b.createdAt - a.createdAt).map((l) => view(l, req)));
  if (p === '/api/links' && m === 'POST') {
    const b = await readBody(req);
    const quotaGB = num(b.quotaGB ?? 0, 0, 100000), expiryDays = num(b.expiryDays ?? 0, 0, 3650);
    if (quotaGB === null || expiryDays === null) return json(res, 400, { error: 'مقدار نامعتبر' });
    const l = store.create({ name: String(b.name || '').trim() || 'کاربر', quotaGB, expiryDays });
    gw.rebuildTrojanIndex();
    return json(res, 201, view(l, req));
  }
  let mm = /^\/api\/links\/([0-9a-f]{8})(?:\/(reset))?$/.exec(p);
  if (mm) {
    const id = mm[1];
    if (!store.get(id)) return json(res, 404, { error: 'not found' });
    if (mm[2] === 'reset' && m === 'POST') return json(res, 200, view(store.resetUsage(id), req));
    if (m === 'PATCH') {
      const b = await readBody(req);
      const patch = {};
      if (typeof b.name === 'string') patch.name = b.name;
      if (typeof b.enabled === 'boolean') patch.enabled = b.enabled;
      if (b.quotaGB !== undefined) { const q = num(b.quotaGB, 0, 100000); if (q === null) return json(res, 400, { error: 'quota' }); patch.quotaGB = q; }
      if (b.expiryDays !== undefined) { const d = num(b.expiryDays, 0, 3650); if (d === null) return json(res, 400, { error: 'expiry' }); patch.expiryDays = d; }
      const l = store.update(id, patch);
      if (patch.enabled === false) gw.closeLink(id);
      return json(res, 200, view(l, req));
    }
    if (m === 'DELETE') { gw.closeLink(id); store.remove(id); gw.rebuildTrojanIndex(); return json(res, 200, { ok: true }); }
  }
  mm = /^\/api\/links\/([0-9a-f]{8})\/qr$/.exec(p);
  if (mm && m === 'GET') {
    const l = store.get(mm[1]); if (!l) return json(res, 404, { error: 'not found' });
    const which = url.searchParams.get('p') === 'trojan' ? 'trojan' : 'vless';
    return send(res, 200, toSvg(uris(req, l)[which]), 'image/svg+xml');
  }
  if (p === '/api/stats' && m === 'GET') {
    const links = store.list();
    return json(res, 200, {
      name: settings.name, uptime: Math.floor((Date.now() - startedAt) / 1000), links: links.length,
      active: links.filter((l) => !store.blockReason(l)).length, live: gw.liveTotal(),
      up: gw.total.up, down: gw.total.down, connections: gw.total.connections, samples: gw.samples.slice(-60),
      mem: process.memoryUsage().rss, load: os.loadavg()[0],
      persistent: !!process.env.DATA_DIR || fs.existsSync('/data'), dataDir: store.dir,
    });
  }
  if (p === '/api/settings' && m === 'GET') return json(res, 200, { configAddress: settings.configAddress || '', configLabel: settings.configLabel || '', upstreamProxy: settings.upstreamProxy ? settings.upstreamProxy.replace(/:\/\/[^@]*@/, '://***@') : '', hasUpstream: !!settings.upstreamProxy, host: publicHost(req).replace(/:\d+$/, '') });
  if (p === '/api/settings' && m === 'POST') {
    const b = await readBody(req);
    const addr = String(b.configAddress || '').trim(), label = String(b.configLabel || '').trim().slice(0, 30);
    if (addr && !ADDR_RE.test(addr)) return json(res, 400, { error: 'آی‌پی یا دامنه نامعتبر است' });
    if (typeof b.upstreamProxy === 'string' && b.upstreamProxy.trim() !== '' && !b.upstreamProxy.includes('***')) {
      if (!socks.parseProxy(b.upstreamProxy)) return json(res, 400, { error: 'فرمت پروکسی: socks5://user:pass@host:port' });
      settings.upstreamProxy = b.upstreamProxy.trim();
    } else if (b.upstreamProxy === '') settings.upstreamProxy = '';
    settings.configAddress = addr; settings.configLabel = label;
    store.saveNow();
    return json(res, 200, { ok: true });
  }
  if (p === '/api/settings/exit' && m === 'POST') {   // which country does traffic really leave from?
    const up = socks.parseProxy(settings.upstreamProxy);
    try {
      const sock = up ? await socks.connect(up, 'ip-api.com', 80, 8000) : require('net').connect({ host: 'ip-api.com', port: 80 });
      const out = await new Promise((ok, no) => {
        let d = ''; const t = setTimeout(() => { sock.destroy(); no(new Error('timeout')); }, 8000);
        sock.on('data', (c) => d += c); sock.on('error', no); sock.on('close', () => { clearTimeout(t); ok(d); });
        sock.write('GET /json?fields=query,country,countryCode HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n');
      });
      const j = JSON.parse(out.slice(out.indexOf('{')));
      return json(res, 200, { ip: j.query, country: j.country, code: j.countryCode, viaProxy: !!up });
    } catch (e) { return json(res, 502, { error: 'تست خروجی ناموفق: ' + e.message }); }
  }
  if (p === '/api/password' && m === 'POST') {
    const b = await readBody(req);
    if (typeof b.next !== 'string' || b.next.length < 8) return json(res, 400, { error: 'رمز جدید حداقل ۸ نویسه باشد' });
    if (!auth.changePassword(b.current || '', b.next)) return json(res, 403, { error: 'رمز فعلی اشتباه است' });
    return json(res, 200, { ok: true }, { 'Set-Cookie': `arses_sid=${auth.makeSession()}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800${isHttps(req) ? '; Secure' : ''}` });
  }
  return json(res, 404, { error: 'not found' });
}

function serveStatic(res, file) {
  const full = path.join(PUB, file);
  if (!full.startsWith(PUB + path.sep)) return send(res, 404, 'Not found', 'text/plain');
  fs.readFile(full, (err, data) => {
    if (err) return send(res, 404, 'Not found', 'text/plain');
    send(res, 200, data, MIME[path.extname(full)] || 'application/octet-stream', { 'Cache-Control': 'public, max-age=300' });
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    if (p.startsWith('/api/')) return await api(req, res, url);
    const authed = !!auth.readSession(req.headers.cookie);
    if (p === '/') return send(res, 302, '', 'text/plain', { Location: authed ? '/dashboard' : '/login' });
    if (p === '/login') return authed ? send(res, 302, '', 'text/plain', { Location: '/dashboard' }) : serveStatic(res, 'login.html');
    if (p === '/dashboard') return authed ? serveStatic(res, 'dashboard.html') : send(res, 302, '', 'text/plain', { Location: '/login' });
    if (/^\/assets\/[\w.-]+$/.test(p)) return serveStatic(res, p.slice(1));
    return send(res, 404, 'Not found', 'text/plain');
  } catch (e) {
    if (!res.headersSent) json(res, 400, { error: e.message === 'too large' ? 'payload too large' : 'bad request' });
  }
});

server.on('upgrade', (req, socket, head) => {
  const p = new URL(req.url, 'http://x').pathname;
  socket.on('error', () => {});
  if (p === settings.vlessPath) return gw.handleUpgrade(req, socket, head, 'vless');
  if (p === settings.trojanPath) return gw.handleUpgrade(req, socket, head, 'trojan');
  socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
});
server.keepAliveTimeout = 65000;
server.headersTimeout = 20000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[arses] listening on :${PORT}  data=${store.dir}`);
  console.log(`[arses] vless path ${settings.vlessPath}   trojan path ${settings.trojanPath}`);
  if (store.dir !== '/data' && !process.env.DATA_DIR) console.warn('[arses] WARNING: no persistent volume - links are lost on redeploy. Mount a volume at /data.');
});

const shutdown = () => { store.saveNow(); process.exit(0); };
process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);
process.on('uncaughtException', (e) => console.error('[arses] uncaught:', e));
process.on('unhandledRejection', (e) => console.error('[arses] unhandled:', e));

'use strict';
// End-to-end test: boots the server, logs in, creates links, and pushes real VLESS/Trojan traffic through it.
const { spawn } = require('child_process');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PORT = 18080, BASE = `http://127.0.0.1:${PORT}`;
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arses-'));
let pass = 0, fail = 0;
const ok = (c, name) => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + name); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const srv = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
  env: { ...process.env, PORT, DATA_DIR: dataDir, ADMIN_USER: 'boss', ADMIN_PASSWORD: 'testpass123', UPSTREAM_PROXY: '', ALLOW_PRIVATE_TARGETS: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
let srvOut = ''; srv.stdout.on('data', (d) => srvOut += d); srv.stderr.on('data', (d) => srvOut += d);

let cookie = '';
async function call(method, p, body, extraHeaders = {}) {
  const r = await fetch(BASE + p, { method, redirect: 'manual', headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...extraHeaders }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await r.text(); let j = null; try { j = JSON.parse(text); } catch {}
  return { status: r.status, json: j, text, headers: r.headers };
}

// ---- upstream servers ----
const echo = net.createServer((s) => s.pipe(s)); // echoes everything
const source = net.createServer((s) => {           // pushes 6 MB of pattern as fast as it can, honouring backpressure
  let sent = 0; const chunk = Buffer.alloc(65536, 0xab);
  (function pump() { while (sent < 6 * 1024 * 1024) { sent += chunk.length; if (!s.write(chunk)) return s.once('drain', pump); } s.end(); })();
});
const listen = (s) => new Promise((r) => s.listen(0, '127.0.0.1', () => r(s.address().port)));

function vlessHeader(uuid, port) {
  const id = Buffer.from(uuid.replace(/-/g, ''), 'hex'); const pb = Buffer.alloc(2); pb.writeUInt16BE(port);
  return Buffer.concat([Buffer.from([0]), id, Buffer.from([0, 1]), pb, Buffer.from([1, 127, 0, 0, 1])]);
}
function trojanHeader(password, port) {
  const pb = Buffer.alloc(2); pb.writeUInt16BE(port);
  return Buffer.concat([Buffer.from(crypto.createHash('sha224').update(password).digest('hex')), Buffer.from('\r\n'), Buffer.from([1, 1, 127, 0, 0, 1]), pb, Buffer.from('\r\n')]);
}
function open(wsPath) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}${wsPath}`); ws.binaryType = 'arraybuffer';
    const st = { ws, got: [], bytes: 0, closed: false, closeCode: null };
    ws.onmessage = (e) => { const b = Buffer.from(e.data); st.got.push(b); st.bytes += b.length; };
    ws.onclose = (e) => { st.closed = true; st.closeCode = e.code; };
    ws.onopen = () => resolve(st); ws.onerror = () => reject(new Error('ws error'));
  });
}
const waitFor = async (fn, ms = 4000) => { const t = Date.now(); while (Date.now() - t < ms) { if (fn()) return true; await sleep(20); } return false; };
const pathOf = (uri) => new URL(uri).searchParams.get('path');

(async () => {
  for (let i = 0; i < 100; i++) { try { if ((await fetch(BASE + '/api/health')).ok) break; } catch {} await sleep(100); }
  const echoPort = await listen(echo), srcPort = await listen(source);

  // ---- web / auth ----
  ok((await call('GET', '/api/links')).status === 401, 'api rejects anonymous');
  ok((await call('GET', '/dashboard')).status === 302, 'dashboard redirects anonymous');
  ok((await call('GET', '/login')).status === 200, 'login page served');
  const loginPage = await call('GET', '/login'); ok(/frame-ancestors/.test(loginPage.headers.get('content-security-policy')), 'CSP header present');
  ok((await call('POST', '/api/login', { username: 'boss', password: 'wrong' })).status === 401, 'wrong password rejected');
  ok((await call('GET', '/api/links', undefined, { Cookie: 'arses_sid=eyJ1IjoiYm9zcyJ9.AAAA' })).status === 401, 'forged cookie rejected');
  const lg = await call('POST', '/api/login', { username: 'boss', password: 'testpass123' });
  ok(lg.status === 200, 'login ok');
  cookie = /arses_sid=[^;]+/.exec(lg.headers.get('set-cookie'))[0];
  ok(/HttpOnly/.test(lg.headers.get('set-cookie')) && /SameSite=Strict/.test(lg.headers.get('set-cookie')), 'cookie is HttpOnly + SameSite=Strict');
  ok((await call('GET', '/dashboard')).status === 200, 'dashboard served when logged in');
  ok((await call('GET', '/assets/dashboard.js')).status === 200, 'static asset served');
  ok((await call('GET', '/assets/..%2F..%2Fserver.js')).status === 404, 'path traversal blocked');
  const noCt = await fetch(BASE + '/api/links', { method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'text/plain' }, body: '{}' });
  ok(noCt.status === 415, 'non-JSON POST rejected (CSRF guard)');

  // ---- links ----
  const mk = await call('POST', '/api/links', { name: 'Ali', quotaGB: 0, expiryDays: 30 });
  ok(mk.status === 201 && /^[0-9a-f-]{36}$/.test(mk.json.uuid), 'link created');
  const L = mk.json; const vpath = pathOf(L.vless), tpath = pathOf(L.trojan);
  ok(vpath && tpath && vpath !== tpath, 'vless/trojan paths differ');
  const qr = await call('GET', `/api/links/${L.id}/qr?p=vless`); ok(qr.status === 200 && qr.text.startsWith('<svg'), 'QR svg served');
  ok((await call('POST', '/api/links', { name: 'x', quotaGB: -1 })).status === 400, 'invalid quota rejected');

  // ---- VLESS relay: echo + integrity + backpressure ----
  {
    const c = await open(vpath);
    c.ws.send(Buffer.concat([vlessHeader(L.uuid, echoPort), Buffer.from('hello')]));
    ok(await waitFor(() => Buffer.concat(c.got).length >= 7), 'vless: got response');
    const all = Buffer.concat(c.got);
    ok(all[0] === 0 && all[1] === 0 && all.subarray(2).toString() === 'hello', 'vless: response header + echoed payload');
    c.got.length = 0; c.bytes = 0;
    const big = crypto.randomBytes(8 * 1024 * 1024); const want = crypto.createHash('sha256').update(big).digest('hex');
    for (let i = 0; i < big.length; i += 65536) c.ws.send(big.subarray(i, i + 65536));
    ok(await waitFor(() => c.bytes >= big.length, 20000), 'vless: 8 MB round trip completed');
    ok(crypto.createHash('sha256').update(Buffer.concat(c.got)).digest('hex') === want, 'vless: 8 MB data integrity (sha256)');
    const st = await call('GET', '/api/stats'); ok(st.json.live >= 1, 'stats: live connection counted');
    c.ws.close();
  }
  // ---- VLESS download direction ----
  {
    const c = await open(vpath);
    c.ws.send(vlessHeader(L.uuid, srcPort));
    ok(await waitFor(() => c.bytes >= 6 * 1024 * 1024 + 2, 15000), 'vless: 6 MB download completed');
    c.ws.close();
  }
  await sleep(300);
  const after = (await call('GET', '/api/links')).json.find((l) => l.id === L.id);
  ok(after.down >= 6 * 1024 * 1024 && after.up >= 8 * 1024 * 1024, 'usage counters updated');

  // ---- Trojan ----
  {
    const c = await open(tpath);
    c.ws.send(Buffer.concat([trojanHeader(L.uuid, echoPort), Buffer.from('trojan-hi')]));
    ok(await waitFor(() => Buffer.concat(c.got).toString() === 'trojan-hi'), 'trojan: echo works');
    c.ws.close();
  }
  { const c = await open(tpath); c.ws.send(Buffer.concat([trojanHeader('not-a-real-password', echoPort), Buffer.from('x')]));
    ok(await waitFor(() => c.closed), 'trojan: wrong password closed'); }

  // ---- wrong uuid / garbage ----
  { const c = await open(vpath); c.ws.send(vlessHeader(crypto.randomUUID(), echoPort)); ok(await waitFor(() => c.closed) && c.bytes === 0, 'vless: unknown uuid rejected'); }
  { const c = await open(vpath); c.ws.send(Buffer.from('GET / HTTP/1.1\r\n\r\n')); ok(await waitFor(() => c.closed), 'vless: garbage rejected'); }
  { const r = await new Promise((res) => { const w = new WebSocket(`ws://127.0.0.1:${PORT}/nope`); w.onerror = () => res('err'); w.onopen = () => res('open'); }); ok(r === 'err', 'unknown ws path refused'); }

  // ---- disable closes live connection ----
  {
    const c = await open(vpath); c.ws.send(Buffer.concat([vlessHeader(L.uuid, echoPort), Buffer.from('a')]));
    await waitFor(() => c.bytes >= 3);
    await call('PATCH', `/api/links/${L.id}`, { enabled: false });
    ok(await waitFor(() => c.closed), 'disable: live connection dropped');
    const d = await open(vpath); d.ws.send(vlessHeader(L.uuid, echoPort)); ok(await waitFor(() => d.closed), 'disable: new connection refused');
    await call('PATCH', `/api/links/${L.id}`, { enabled: true });
  }

  // ---- quota enforcement ----
  {
    const q = (await call('POST', '/api/links', { name: 'Small', quotaGB: 0.0005, expiryDays: 0 })).json; // ~524 KB
    const c = await open(pathOf(q.vless)); c.ws.send(Buffer.concat([vlessHeader(q.uuid, echoPort), Buffer.from('x')]));
    const blob = crypto.randomBytes(64 * 1024);
    for (let i = 0; i < 40 && !c.closed; i++) { try { c.ws.send(blob); } catch {} await sleep(15); }
    ok(await waitFor(() => c.closed), 'quota: connection cut when exceeded');
    ok(c.bytes < 2 * 1024 * 1024, 'quota: traffic stopped near the limit');
    const lq = (await call('GET', '/api/links')).json.find((l) => l.id === q.id);
    ok(lq.status === 'quota', 'quota: status = quota');
    const d = await open(pathOf(q.vless)); d.ws.send(vlessHeader(q.uuid, echoPort)); ok(await waitFor(() => d.closed), 'quota: new connection refused');
    await call('POST', `/api/links/${q.id}/reset`, {}); const d2 = await open(pathOf(q.vless)); d2.ws.send(Buffer.concat([vlessHeader(q.uuid, echoPort), Buffer.from('y')]));
    ok(await waitFor(() => d2.bytes >= 3), 'quota: works again after reset'); d2.ws.close();
  }

  // ---- early data (Sec-WebSocket-Protocol) ----
  {
    const first = Buffer.concat([vlessHeader(L.uuid, echoPort), Buffer.from('ED')]).toString('base64url');
    const r = await new Promise((resolve) => { const s = net.connect(PORT, '127.0.0.1'); let buf = Buffer.alloc(0);
      s.on('connect', () => s.write(`GET ${vpath} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: ${first}\r\n\r\n`));
      s.on('data', (d) => { buf = Buffer.concat([buf, d]); if (buf.includes('ED')) { resolve(buf.toString('latin1')); s.destroy(); } });
      setTimeout(() => resolve(buf.toString('latin1')), 3000); });
    ok(/101 Switching/.test(r) && r.includes('ED'), 'early-data in Sec-WebSocket-Protocol works');
  }

  // ---- SSRF guard (flag is off inside this process) ----
  const { isBlockedIp } = require('../src/relay');
  ok(['127.0.0.1', '10.0.0.5', '172.16.9.9', '192.168.1.1', '169.254.169.254', '::1', 'fd12::1', '::ffff:10.0.0.1', '100.64.0.1'].every(isBlockedIp), 'guard: private/loopback/metadata ranges blocked');
  ok(!isBlockedIp('8.8.8.8') && !isBlockedIp('2606:4700::1111'), 'guard: public addresses allowed');

  // ---- persistence ----
  await call('POST', '/api/links', { name: 'persist-me' });
  srv.kill('SIGTERM'); await sleep(500);
  const saved = JSON.parse(fs.readFileSync(path.join(dataDir, 'arses.json'), 'utf8'));
  ok(Object.values(saved.links).some((l) => l.name === 'persist-me'), 'state saved to disk on shutdown');
  ok(!JSON.stringify(saved.admin).includes('testpass123'), 'admin password stored hashed only');

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail) console.log('--- server log ---\n' + srvOut);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('TEST CRASH', e, srvOut); srv.kill(); process.exit(1); });

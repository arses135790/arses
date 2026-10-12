'use strict';
// VLESS / Trojan over WebSocket -> TCP relay with per-link accounting.
const net = require('net');
const dns = require('dns');
const crypto = require('crypto');
const { accept } = require('./ws');
const socks = require('./socks');

// Never let a client reach the host's own network (loopback, Railway private network, metadata, ...).
const blocked = new net.BlockList();
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4]]) blocked.addSubnet(a, p, 'ipv4');
for (const [a, p] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['64:ff9b::', 96]]) blocked.addSubnet(a, p, 'ipv6');

function isBlockedIp(ip) {
  if (process.env.ALLOW_PRIVATE_TARGETS === '1') return false;   // tests only
  const fam = net.isIPv4(ip) ? 'ipv4' : 'ipv6';
  if (fam === 'ipv6') {                                  // ::ffff:a.b.c.d
    const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
    if (m) return blocked.check(m[1], 'ipv4');
  }
  return blocked.check(ip, fam);
}

const BLOCKED_PORTS = new Set((process.env.BLOCKED_PORTS || '25').split(',').map((s) => Number(s.trim())).filter(Boolean));

const dnsCache = new Map();                              // host -> {all, exp}; saves a lookup round-trip on every new connection
setInterval(() => { const n = Date.now(); for (const [k, v] of dnsCache) if (v.exp < n) dnsCache.delete(k); }, 60000).unref();
async function lookupCached(host) {
  const c = dnsCache.get(host);
  if (c && c.exp > Date.now()) return c.all;
  const all = await dns.promises.lookup(host, { all: true });
  if (dnsCache.size < 5000) dnsCache.set(host, { all, exp: Date.now() + 60000 });
  return all;
}

async function resolveSafe(host) {
  if (net.isIP(host)) { if (isBlockedIp(host)) throw new Error('blocked address'); return host; }
  const all = await lookupCached(host);
  const ok = all.filter((a) => !isBlockedIp(a.address));
  if (!ok.length) throw new Error('blocked address');
  ok.sort((a, b) => a.family - b.family);               // prefer IPv4
  return ok[0].address;
}

function readAddr(buf, off, type) {                      // returns [host, nextOffset] or null
  if (type === 'ipv4') { if (buf.length < off + 4) return null; return [Array.from(buf.subarray(off, off + 4)).join('.'), off + 4]; }
  if (type === 'ipv6') {
    if (buf.length < off + 16) return null;
    const parts = []; for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(off + i).toString(16));
    return [parts.join(':'), off + 16];
  }
  if (buf.length < off + 1) return null;
  const n = buf[off]; if (!n || buf.length < off + 1 + n) return null;
  return [buf.toString('utf8', off + 1, off + 1 + n), off + 1 + n];
}

// VLESS: ver(1) uuid(16) addonsLen(1) addons cmd(1) port(2) atype(1) addr
function parseVless(buf) {
  if (buf.length < 24 || buf[0] !== 0) return null;
  const u = buf.subarray(1, 17).toString('hex');
  const uuid = `${u.slice(0, 8)}-${u.slice(8, 12)}-${u.slice(12, 16)}-${u.slice(16, 20)}-${u.slice(20)}`;
  let off = 18 + buf[17];
  if (buf.length < off + 4) return null;
  const cmd = buf[off]; const port = buf.readUInt16BE(off + 1); const at = buf[off + 3];
  const type = at === 1 ? 'ipv4' : at === 2 ? 'domain' : at === 3 ? 'ipv6' : null;
  if (!type) return null;
  const a = readAddr(buf, off + 4, type); if (!a) return null;
  return { uuid, cmd, port, host: a[0], rest: buf.subarray(a[1]), reply: Buffer.from([0, 0]) };
}

// Trojan: hex(sha224(password))(56) CRLF cmd(1) atype(1) addr port(2) CRLF payload
function parseTrojan(buf, byHash) {
  if (buf.length < 62) return null;
  const hash = buf.toString('latin1', 0, 56);
  const link = byHash.get(hash);
  if (!link || buf[56] !== 0x0d || buf[57] !== 0x0a) return null;
  const cmd = buf[58]; const at = buf[59];
  const type = at === 1 ? 'ipv4' : at === 3 ? 'domain' : at === 4 ? 'ipv6' : null;
  if (!type) return null;
  const a = readAddr(buf, 60, type); if (!a || buf.length < a[1] + 4) return null;
  const port = buf.readUInt16BE(a[1]);
  if (buf[a[1] + 2] !== 0x0d || buf[a[1] + 3] !== 0x0a) return null;
  return { uuid: link.uuid, cmd, port, host: a[0], rest: buf.subarray(a[1] + 4), reply: null };
}

class Gateway {
  constructor(store) {
    this.store = store;
    this.live = new Map();                 // link id -> Set<conn>
    this.trojanIndex = new Map();
    this.total = { up: 0, down: 0, connections: 0 };
    this.samples = [];                     // {t, up, down} per 5 s (bytes in interval)
    this._last = { up: 0, down: 0 };
    this.rebuildTrojanIndex();
    setInterval(() => this.sweep(), 5000).unref();
  }

  rebuildTrojanIndex() {
    this.trojanIndex.clear();
    for (const l of this.store.list()) this.trojanIndex.set(crypto.createHash('sha224').update(l.uuid).digest('hex'), l);
  }

  liveCount(id) { return this.live.get(id)?.size || 0; }
  liveTotal() { let n = 0; for (const s of this.live.values()) n += s.size; return n; }

  // Close connections of links that became unusable; record throughput sample.
  sweep() {
    for (const [id, set] of this.live) {
      const l = this.store.get(id);
      if (!l || this.store.blockReason(l)) for (const c of [...set]) c.kill();
    }
    this.samples.push({ t: Date.now(), up: this.total.up - this._last.up, down: this.total.down - this._last.down });
    this._last = { up: this.total.up, down: this.total.down };
    if (this.samples.length > 120) this.samples.shift();
  }

  closeLink(id) { for (const c of [...(this.live.get(id) || [])]) c.kill(); }

  handleUpgrade(req, socket, head, proto) {
    const ws = accept(req, socket, head);
    if (!ws) return;
    const state = { link: null, target: null, started: false, dead: false };
    const conn = { kill: () => { state.dead = true; ws.close(1000); state.target?.destroy(); } };

    const cleanup = () => {
      state.dead = true;
      state.target?.destroy();
      if (state.link) {
        const set = this.live.get(state.link.id);
        if (set) { set.delete(conn); if (!set.size) this.live.delete(state.link.id); }
        state.link.lastSeen = Date.now(); this.store.saveSoon();
      }
    };
    ws.on('close', cleanup);

    const onFirst = async (msg) => {
      const hdr = proto === 'vless' ? parseVless(msg) : parseTrojan(msg, this.trojanIndex);
      if (!hdr || hdr.cmd !== 1) return ws.close(1008);   // only TCP CONNECT is supported
      const link = proto === 'vless' ? this.store.byUuid(hdr.uuid) : this.trojanIndex.get(
        crypto.createHash('sha224').update(hdr.uuid).digest('hex'));
      if (!link || this.store.blockReason(link) || BLOCKED_PORTS.has(hdr.port)) return ws.close(1008);
      let ip;
      try { ip = await resolveSafe(hdr.host); } catch { return ws.close(1008); }
      if (state.dead) return;
      state.link = link;
      if (!this.live.has(link.id)) this.live.set(link.id, new Set());
      this.live.get(link.id).add(conn);
      this.total.connections++;
      const up = socks.parseProxy(this.store.data.settings.upstreamProxy);
      let target;
      if (up) {                                          // exit through the upstream proxy (e.g. UAE); never fall back to direct
        try { target = await socks.connect(up, net.isIP(hdr.host) ? ip : hdr.host, hdr.port); } catch { return ws.close(1011); }
        if (state.dead) return target.destroy();
      } else target = net.connect({ host: ip, port: hdr.port });
      state.target = target;
      target.setNoDelay(true);
      target.setKeepAlive(true, 30000);
      target.setTimeout(0);
      const ct = up ? null : setTimeout(() => target.destroy(), 10000);
      let replied = hdr.reply === null;
      const onConnected = () => {
        clearTimeout(ct);
        if (hdr.rest.length) { link.up += hdr.rest.length; this.total.up += hdr.rest.length; target.write(hdr.rest); }
        state.started = true;
      };
      if (up) onConnected(); else target.on('connect', onConnected);
      target.on('data', (d) => {
        link.down += d.length; this.total.down += d.length;
        const out = replied ? d : Buffer.concat([hdr.reply, d]);
        replied = true;
        if (ws.send(out) === false) { target.pause(); ws.once('drain', () => target.resume()); }
      });
      for (const m of state.queue.splice(0)) this._up(state, m, ws);
      target.on('error', () => { clearTimeout(ct); ws.close(1011); });
      target.on('close', () => { clearTimeout(ct); ws.close(1000); });
    };

    let first = false; let qBytes = 0; const queue = [];
    state.queue = queue;
    ws.on('message', (msg) => {
      if (state.dead) return;
      if (!first) { first = true; onFirst(msg).catch(() => ws.close(1011)); return; }
      if (!state.target) {                       // still resolving DNS: hold early frames
        qBytes += msg.length;
        if (qBytes > (1 << 20)) return ws.close(1009);
        queue.push(msg); return;
      }
      this._up(state, msg, ws);
    });

    if (ws.earlyData) ws.emit('message', ws.earlyData, true);
  }

  _up(state, msg, ws) {
    const { link, target } = state;
    if (!target || target.destroyed) return;
    link.up += msg.length; this.total.up += msg.length;
    if (link.quotaBytes && link.up + link.down >= link.quotaBytes) return ws.close(1008);
    if (target.write(msg) === false) { ws.pause(); target.once('drain', () => ws.resume()); }
  }
}

module.exports = { Gateway, parseVless, parseTrojan, isBlockedIp };

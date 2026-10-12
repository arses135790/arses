'use strict';
// Minimal SOCKS5 client (CONNECT, optional user/pass) used to send traffic out through an upstream exit (e.g. a UAE proxy).
const net = require('net');

function parseProxy(url) {
  const m = /^socks5h?:\/\/(?:([^:@\/]*):([^@\/]*)@)?(\[[^\]]+\]|[^:\/]+):(\d{1,5})\/?$/i.exec(String(url || '').trim());
  if (!m) return null;
  const port = Number(m[4]); if (!port || port > 65535) return null;
  return { user: m[1] ? decodeURIComponent(m[1]) : '', pass: m[2] ? decodeURIComponent(m[2]) : '', host: m[3].replace(/^\[|\]$/g, ''), port };
}

function connect(proxy, host, port, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: proxy.host, port: proxy.port });
    let buf = Buffer.alloc(0), step = 0, done = false;
    const fail = (e) => { if (done) return; done = true; s.destroy(); reject(e instanceof Error ? e : new Error(e)); };
    const timer = setTimeout(() => fail('socks timeout'), timeout);
    const hasAuth = !!(proxy.user || proxy.pass);
    s.setNoDelay(true);
    s.once('error', fail);
    s.once('connect', () => s.write(Buffer.from(hasAuth ? [5, 2, 0, 2] : [5, 1, 0])));
    const sendConnect = () => {
      let addr;
      if (net.isIPv4(host)) addr = Buffer.from([1, ...host.split('.').map(Number)]);
      else if (net.isIPv6(host)) { const b = Buffer.alloc(17); b[0] = 4; require('net'); const parts = expand6(host); parts.forEach((p, i) => b.writeUInt16BE(p, 1 + i * 2)); addr = b; }
      else { const h = Buffer.from(host); addr = Buffer.concat([Buffer.from([3, h.length]), h]); }
      const pb = Buffer.alloc(2); pb.writeUInt16BE(port);
      s.write(Buffer.concat([Buffer.from([5, 1, 0]), addr, pb]));
    };
    s.on('data', function onData(d) {
      if (done) return;
      buf = Buffer.concat([buf, d]);
      for (;;) {
        if (step === 0) {
          if (buf.length < 2) return;
          if (buf[0] !== 5 || buf[1] === 0xff) return fail('socks method rejected');
          const method = buf[1]; buf = buf.subarray(2);
          if (method === 2) {
            const u = Buffer.from(proxy.user), p = Buffer.from(proxy.pass);
            s.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([p.length]), p])); step = 1;
          } else if (method === 0) { sendConnect(); step = 2; } else return fail('socks method unsupported');
        } else if (step === 1) {
          if (buf.length < 2) return;
          if (buf[1] !== 0) return fail('socks auth failed');
          buf = buf.subarray(2); sendConnect(); step = 2;
        } else {
          if (buf.length < 5) return;
          if (buf[1] !== 0) return fail('socks connect refused (' + buf[1] + ')');
          const need = buf[3] === 1 ? 10 : buf[3] === 4 ? 22 : 7 + buf[4];
          if (buf.length < need) return;
          const rest = buf.subarray(need);
          done = true; clearTimeout(timer); s.removeListener('error', fail); s.removeAllListeners('data');
          if (rest.length) s.unshift(rest);
          return resolve(s);
        }
      }
    });
    s.once('close', () => fail('socks closed'));
  });
}

function expand6(ip) {
  const [a, b = ''] = ip.split('::');
  const l = a ? a.split(':') : [], r = b ? b.split(':') : [];
  const mid = ip.includes('::') ? Array(8 - l.length - r.length).fill('0') : [];
  return [...l, ...mid, ...r].map((x) => parseInt(x || '0', 16));
}

module.exports = { parseProxy, connect };

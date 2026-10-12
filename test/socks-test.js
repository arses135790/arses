'use strict';
const net = require('net');
const socks = require('../src/socks');
let fail = 0; const ok = (c, n) => { if (!c) fail++; console.log((c ? 'PASS ' : 'FAIL ') + n); };
// fake SOCKS5 server with user/pass auth, echoing after CONNECT; records requested target
let seen = null;
const srv = net.createServer((s) => {
  let st = 0, buf = Buffer.alloc(0);
  s.on('data', (d) => {
    if (st === 3) return s.write(d);
    buf = Buffer.concat([buf, d]);
    if (st === 0 && buf.length >= 4) { s.write(Buffer.from([5, 2])); buf = Buffer.alloc(0); st = 1; }
    else if (st === 1 && buf.length >= 3) {
      const ul = buf[1], u = buf.toString('utf8', 2, 2 + ul), pl = buf[2 + ul], p = buf.toString('utf8', 3 + ul, 3 + ul + pl);
      s.write(Buffer.from([1, u === 'u' && p === 'p' ? 0 : 1])); buf = Buffer.alloc(0); st = u === 'u' && p === 'p' ? 2 : 9;
    } else if (st === 2 && buf.length >= 7) {
      const at = buf[3]; seen = at === 3 ? buf.toString('utf8', 5, 5 + buf[4]) : 'ip:' + [...buf.subarray(4, 8)].join('.');
      s.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); st = 3;
    }
  });
});
srv.listen(0, '127.0.0.1', async () => {
  const port = srv.address().port;
  ok(!!socks.parseProxy('socks5://u:p@1.2.3.4:1080') && !socks.parseProxy('http://x:1'), 'parseProxy');
  const s = await socks.connect({ host: '127.0.0.1', port, user: 'u', pass: 'p' }, 'example.com', 443);
  const got = await new Promise((r) => { s.once('data', (d) => r(d.toString())); s.write('hello'); });
  ok(got === 'hello' && seen === 'example.com', 'connect via socks5 with auth, domain passed to proxy, data relayed');
  const bad = await socks.connect({ host: '127.0.0.1', port, user: 'u', pass: 'x' }, '8.8.8.8', 53).then(() => false, () => true);
  ok(bad, 'wrong credentials rejected');
  srv.close(); process.exit(fail ? 1 : 0);
});

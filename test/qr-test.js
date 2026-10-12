const { toSvg } = require('../src/qr');
const fs = require('fs');
const out = process.argv[2];
let i = 0;
for (const len of [5, 17, 30, 60, 100, 140, 180, 220, 260, 300, 340, 400, 450, 500, 560, 620, 680]) {
  let t = 'vless://' + 'aB3-_.~'.repeat(200); t = t.slice(0, len);
  fs.writeFileSync(`${out}/q${len}.svg`, toSvg(t));
  fs.writeFileSync(`${out}/q${len}.txt`, t);
}

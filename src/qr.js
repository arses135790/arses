'use strict';
// Compact QR Code generator: byte mode, error-correction level L, versions 1-20, SVG output.
// Algorithm follows ISO/IEC 18004 (Reed-Solomon over GF(256), 8 mask patterns, penalty scoring).
const ECC_PER_BLOCK = [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28];
const NUM_BLOCKS    = [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8];

function rawModules(v) {
  let r = (16 * v + 128) * v + 64;
  if (v >= 2) { const n = Math.floor(v / 7) + 2; r -= (25 * n - 10) * n - 55; if (v >= 7) r -= 36; }
  return r;
}
const dataCodewords = (v) => Math.floor(rawModules(v) / 8) - ECC_PER_BLOCK[v] * NUM_BLOCKS[v];

// GF(256) with primitive polynomial 0x11D
const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const gmul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

function rsGenerator(deg) {
  let g = [1];
  for (let i = 0; i < deg; i++) {
    const n = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) { n[j] ^= g[j]; n[j + 1] ^= gmul(g[j], EXP[i]); }
    g = n;
  }
  return g;
}
function rsRemainder(data, deg) {
  const g = rsGenerator(deg), res = new Array(deg).fill(0);
  for (const b of data) {
    const f = b ^ res.shift(); res.push(0);
    for (let i = 0; i < deg; i++) res[i] ^= gmul(g[i + 1], f);
  }
  return res;
}

function encodeData(bytes, v) {
  const bits = [];
  const put = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  put(0b0100, 4); put(bytes.length, v <= 9 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  const cap = dataCodewords(v) * 8;
  put(0, Math.min(4, cap - bits.length));
  while (bits.length % 8) bits.push(0);
  for (let pad = 0xEC; bits.length < cap; pad ^= 0xEC ^ 0x11) put(pad, 8);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) { let b = 0; for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j]; out.push(b); }
  return out;
}

function interleave(data, v) {
  const nb = NUM_BLOCKS[v], ecl = ECC_PER_BLOCK[v];
  const raw = Math.floor(rawModules(v) / 8);
  const shortBlocks = nb - (raw % nb), shortLen = Math.floor(raw / nb) - ecl;
  const blocks = []; let k = 0;
  for (let i = 0; i < nb; i++) {
    const len = shortLen + (i < shortBlocks ? 0 : 1);
    const d = data.slice(k, k + len); k += len;
    blocks.push({ d, e: rsRemainder(d, ecl) });
  }
  const out = [];
  for (let i = 0; i <= shortLen; i++) blocks.forEach((b, j) => { if (i < shortLen || j >= shortBlocks) out.push(b.d[i]); });
  for (let i = 0; i < ecl; i++) blocks.forEach((b) => out.push(b.e[i]));
  return out;
}

function alignmentPositions(v) {
  if (v === 1) return [];
  const n = Math.floor(v / 7) + 2, size = v * 4 + 17;
  const step = v === 32 ? 26 : Math.ceil((v * 4 + 4) / (n * 2 - 2)) * 2;
  const r = [6];
  for (let p = size - 7; r.length < n; p -= step) r.splice(1, 0, p);
  return r;
}

function build(codewords, v, mask) {
  const size = v * 4 + 17;
  const m = Array.from({ length: size }, () => new Array(size).fill(false));
  const fn = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, dark) => { m[y][x] = dark; fn[y][x] = true; };

  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy; if (x < 0 || y < 0 || x >= size || y >= size) continue;
      const d = Math.max(Math.abs(dx), Math.abs(dy)); set(x, y, d !== 2 && d !== 4);
    }
  };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
  const ap = alignmentPositions(v);
  for (let i = 0; i < ap.length; i++) for (let j = 0; j < ap.length; j++) {
    if ((i === 0 && j === 0) || (i === 0 && j === ap.length - 1) || (i === ap.length - 1 && j === 0)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ap[i] + dx, ap[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }

  // format bits (level L = 01)
  const fmtData = (0b01 << 3) | mask;
  let rem = fmtData; for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const fmt = ((fmtData << 10) | rem) ^ 0x5412;
  const bit = (i) => ((fmt >>> i) & 1) !== 0;
  for (let i = 0; i <= 5; i++) set(8, i, bit(i));
  set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
  set(8, size - 8, true);

  if (v >= 7) {
    let r = v; for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25);
    const bits = (v << 12) | r;
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3), b = Math.floor(i / 3), d = ((bits >>> i) & 1) !== 0;
      set(a, b, d); set(b, a, d);
    }
  }

  // place data
  let bi = 0; const total = codewords.length * 8;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j, up = ((right + 1) & 2) === 0, y = up ? size - 1 - vert : vert;
      if (fn[y][x]) continue;
      let dark = false;
      if (bi < total) { dark = ((codewords[bi >>> 3] >>> (7 - (bi & 7))) & 1) !== 0; bi++; }
      const inv = [(x + y) % 2 === 0, y % 2 === 0, x % 3 === 0, (x + y) % 3 === 0,
        (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, ((x * y) % 2) + ((x * y) % 3) === 0,
        (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (((x + y) % 2) + ((x * y) % 3)) % 2 === 0][mask];
      m[y][x] = dark !== inv;
    }
  }
  return m;
}

function penalty(m) {
  const n = m.length; let p = 0;
  const run = (line) => {
    let s = 0, c = 1;
    for (let i = 1; i <= line.length; i++) {
      if (i < line.length && line[i] === line[i - 1]) c++; else { if (c >= 5) s += c - 2; c = 1; }
    }
    return s;
  };
  for (let y = 0; y < n; y++) { p += run(m[y]); p += run(m.map((r) => r[y])); }
  for (let y = 0; y < n - 1; y++) for (let x = 0; x < n - 1; x++) {
    const c = m[y][x]; if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) p += 3;
  }
  const pat = [true, false, true, true, true, false, true, false, false, false, false];
  const rev = [...pat].reverse();
  const find = (get) => { let s = 0; for (let i = 0; i + 11 <= n; i++) {
    if (pat.every((v, k) => get(i + k) === v)) s += 40; if (rev.every((v, k) => get(i + k) === v)) s += 40; } return s; };
  for (let y = 0; y < n; y++) { p += find((i) => m[y][i]); p += find((i) => m[i][y]); }
  let dark = 0; for (const r of m) for (const c of r) if (c) dark++;
  p += Math.floor(Math.abs(dark * 20 - n * n * 10) / (n * n)) * 10;
  return p;
}

function encode(text) {
  const bytes = Buffer.from(String(text), 'utf8');
  let v = 1;
  while (v <= 20 && (v <= 9 ? 12 : 20) + bytes.length * 8 > dataCodewords(v) * 8) v++;
  if (v > 20) throw new Error('text too long for QR');
  const cw = interleave(encodeData(bytes, v), v);
  let best = null, bp = Infinity;
  for (let mask = 0; mask < 8; mask++) { const mm = build(cw, v, mask), p = penalty(mm); if (p < bp) { bp = p; best = mm; } }
  return best;
}

function toSvg(text, { border = 4, dark = '#000', light = '#fff' } = {}) {
  const m = encode(text), n = m.length, s = n + border * 2;
  let d = '';
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (m[y][x]) d += `M${x + border},${y + border}h1v1h-1z`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${s} ${s}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="${light}"/><path d="${d}" fill="${dark}"/></svg>`;
}

module.exports = { toSvg, encode };

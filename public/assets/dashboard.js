'use strict';
const $ = (id) => document.getElementById(id);
const GB = 1024 ** 3;

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v; else if (k === 'style') e.style.cssText = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}
function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (n >= 100 || i === 0 ? n.toFixed(0) : n.toFixed(2)) + ' ' + u[i];
}
function fmtUptime(s) {
  const d = Math.floor(s / 86400), hr = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return d ? `${d}d ${hr}h` : hr ? `${hr}h ${m}m` : `${m}m`;
}
function toast(msg) { const t = $('toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), 1800); }

async function api(path, method = 'GET', body) {
  const r = await fetch(path, { method, headers: body !== undefined ? { 'Content-Type': 'application/json' } : (method !== 'GET' ? { 'Content-Type': 'application/json' } : {}),
    body: body !== undefined ? JSON.stringify(body) : (method !== 'GET' ? '{}' : undefined) });
  if (r.status === 401) { location.href = '/login'; throw new Error('auth'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'خطا');
  return j;
}

async function copy(text) {
  try { await navigator.clipboard.writeText(text); }
  catch { const t = h('textarea'); t.value = text; document.body.append(t); t.select(); document.execCommand('copy'); t.remove(); }
  toast('کپی شد');
}

// ---------- stats + chart ----------
function renderStats(s) {
  const card = (k, v) => h('div', { class: 'card stat' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v));
  $('stats').replaceChildren(
    card('اتصال زنده', s.live), card('لینک فعال / کل', `${s.active} / ${s.links}`),
    card('دانلود کل', fmtBytes(s.down)), card('آپلود کل', fmtBytes(s.up)), card('آپ‌تایم', fmtUptime(s.uptime)));
  $('banner').replaceChildren(s.persistent ? '' : h('div', { class: 'banner' },
    'ذخیره‌سازی دائمی فعال نیست: با هر دیپلوی مجدد، لینک‌ها پاک می‌شوند. روی Railway یک Volume با مسیر /data وصل کنید.'));
  drawChart(s.samples);
}
function drawChart(samples) {
  const c = $('chart'), dpr = window.devicePixelRatio || 1, w = c.clientWidth, hgt = 150;
  c.width = w * dpr; c.height = hgt * dpr;
  const g = c.getContext('2d'); g.scale(dpr, dpr); g.clearRect(0, 0, w, hgt);
  const cs = getComputedStyle(document.documentElement);
  const rate = (x) => x / 5;                                     // bytes/s over 5 s buckets
  const max = Math.max(1024, ...samples.map((s) => Math.max(rate(s.up), rate(s.down)))) * 1.15;
  g.strokeStyle = cs.getPropertyValue('--line'); g.lineWidth = 1; g.fillStyle = cs.getPropertyValue('--mut'); g.font = '11px sans-serif'; g.direction = 'ltr'; g.textAlign = 'left';
  for (let i = 0; i <= 3; i++) {
    const y = 10 + (hgt - 22) * i / 3; g.beginPath(); g.moveTo(0, y); g.lineTo(w, y); g.stroke();
    g.fillText(fmtBytes(max * (1 - i / 3)) + '/s', 4, y - 3);
  }
  const line = (key, color) => {
    if (samples.length < 2) return;
    g.strokeStyle = cs.getPropertyValue(color).trim(); g.lineWidth = 2; g.beginPath();
    samples.forEach((s, i) => { const x = w * i / (60 - 1) + (w - w * (samples.length - 1) / 59), y = 10 + (hgt - 22) * (1 - rate(s[key]) / max); i ? g.lineTo(x, y) : g.moveTo(x, y); });
    g.stroke();
  };
  line('down', '--acc'); line('up', '--acc2');
}

// ---------- links ----------
const STATUS = { active: 'فعال', disabled: 'غیرفعال', expired: 'منقضی', quota: 'حجم تمام شد' };
function expiryText(l) {
  if (!l.expiresAt) return 'بدون انقضا';
  const d = Math.ceil((l.expiresAt - Date.now()) / 86400000);
  return d > 0 ? `${d} روز مانده` : 'منقضی شده';
}
function renderLinks(list) {
  if (!list.length) return $('links').replaceChildren(h('div', { class: 'card empty' }, 'هنوز لینکی نساخته‌اید. «لینک جدید» را بزنید.'));
  $('links').replaceChildren(...list.map((l) => {
    const pct = l.quotaBytes ? Math.min(100, l.used / l.quotaBytes * 100) : 0;
    return h('div', { class: 'card link' },
      h('div', {}, h('div', { class: 'nm' }, l.name, h('span', { class: 'badge ' + l.status }, STATUS[l.status])),
        h('div', { class: 'sub' }, expiryText(l), ' · اتصال زنده: ', l.live)),
      h('div', {}, h('div', { class: 'sub ltr' }, `${fmtBytes(l.used)} / ${l.quotaBytes ? fmtBytes(l.quotaBytes) : '∞'}`),
        l.quotaBytes ? h('div', { class: 'meter' + (pct > 85 ? ' hot' : '') }, h('i', { style: `width:${pct}%` })) : null,
        h('div', { class: 'sub ltr' }, `↓ ${fmtBytes(l.down)}  ↑ ${fmtBytes(l.up)}`)),
      h('div', {}, h('button', { class: 'btn sm', onclick: async () => { await api('/api/links/' + l.id, 'PATCH', { enabled: !l.enabled }); refresh(); } }, l.enabled ? 'غیرفعال کن' : 'فعال کن')),
      h('div', { class: 'acts' },
        h('button', { class: 'btn sm', onclick: () => copy(l.vless) }, 'VLESS'),
        h('button', { class: 'btn sm', onclick: () => copy(l.trojan) }, 'Trojan'),
        h('button', { class: 'btn sm', onclick: () => showQr(l) }, 'QR'),
        h('button', { class: 'btn sm', onclick: () => openEdit(l) }, 'ویرایش'),
        h('button', { class: 'btn sm', onclick: async () => { if (confirm('مصرف این لینک صفر شود؟')) { await api(`/api/links/${l.id}/reset`, 'POST'); refresh(); } } }, 'ریست حجم'),
        h('button', { class: 'btn sm danger', onclick: async () => { if (confirm(`«${l.name}» حذف شود؟`)) { await api('/api/links/' + l.id, 'DELETE'); refresh(); } } }, 'حذف')));
  }));
}

// ---------- dialogs ----------
let editing = null;
function openEdit(l) {
  editing = l;
  $('eTitle').textContent = l ? 'ویرایش لینک' : 'لینک جدید';
  $('eName').value = l ? l.name : '';
  $('eQuota').value = l ? +(l.quotaBytes / GB).toFixed(2) : 0;
  $('eDays').value = l ? '' : 0;
  $('eDays').placeholder = l ? 'خالی = بدون تغییر' : '';
  $('eDaysL').textContent = l ? 'اعتبار از امروز (روز؛ ۰ = بدون انقضا؛ خالی = بدون تغییر)' : 'اعتبار (روز، ۰ = بدون انقضا)';
  $('eErr').textContent = '';
  $('dEdit').showModal();
}
$('fEdit').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = { name: $('eName').value.trim(), quotaGB: Number($('eQuota').value || 0) };
  if ($('eDays').value !== '') body.expiryDays = Number($('eDays').value);
  try {
    if (editing) await api('/api/links/' + editing.id, 'PATCH', body); else await api('/api/links', 'POST', body);
    $('dEdit').close(); refresh();
  } catch (err) { $('eErr').textContent = err.message; }
});

let qrLink = null, qrProto = 'vless';
function showQr(l) { qrLink = l; qrProto = 'vless'; $('qTitle').textContent = l.name; updQr(); $('dQr').showModal(); }
function updQr() {
  $('qImg').src = `/api/links/${qrLink.id}/qr?p=${qrProto}`;
  $('qUri').textContent = qrLink[qrProto];
  document.querySelectorAll('#dQr .tabs .btn').forEach((b) => b.classList.toggle('on', b.dataset.p === qrProto));
}
document.querySelectorAll('#dQr .tabs .btn').forEach((b) => b.addEventListener('click', () => { qrProto = b.dataset.p; updQr(); }));
$('qCopy').addEventListener('click', () => copy(qrLink[qrProto]));
document.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => b.closest('dialog').close()));

$('btnSet').addEventListener('click', async () => {
  $('sErr').textContent = '';
  try { const c = await api('/api/settings'); $('sAddr').value = c.configAddress; $('sLabel').value = c.configLabel; $('sHost').textContent = 'SNI / Host: ' + c.host; $('sUp').value = ''; $('sUp').placeholder = c.hasUpstream ? 'فعال: ' + c.upstreamProxy + ' (برای تغییر، جدید را بنویسید)' : 'socks5://user:pass@ip:port'; $('sTestOut').textContent = ''; $('dSet').showModal(); }
  catch (err) { toast(err.message); }
});
$('fSet').addEventListener('submit', async (e) => {
  e.preventDefault();
  try { await api('/api/settings', 'POST', { configAddress: $('sAddr').value, configLabel: $('sLabel').value, upstreamProxy: $('sUp').value }); $('dSet').close(); toast('ذخیره شد'); refresh(); }
  catch (err) { $('sErr').textContent = err.message; }
});
$('sTest').addEventListener('click', async () => {
  $('sTestOut').textContent = '...';
  try {
    if ($('sUp').value.trim()) await api('/api/settings', 'POST', { configAddress: $('sAddr').value, configLabel: $('sLabel').value, upstreamProxy: $('sUp').value });
    const r = await api('/api/settings/exit', 'POST', {}); $('sTestOut').textContent = `${r.ip} — ${r.country} (${r.code})${r.viaProxy ? ' via proxy' : ' (مستقیم، بدون پروکسی)'}`;
  } catch (err) { $('sTestOut').textContent = err.message; }
});
$('sClear').addEventListener('click', async () => {
  try { await api('/api/settings', 'POST', { configAddress: $('sAddr').value, configLabel: $('sLabel').value, upstreamProxy: '' }); $('sUp').placeholder = 'socks5://user:pass@ip:port'; toast('پروکسی حذف شد'); } catch (err) { toast(err.message); }
});
$('btnNew').addEventListener('click', () => openEdit(null));
$('btnPass').addEventListener('click', () => { $('pErr').textContent = ''; $('fPass').reset(); $('dPass').showModal(); });
$('fPass').addEventListener('submit', async (e) => {
  e.preventDefault();
  try { await api('/api/password', 'POST', { current: $('pCur').value, next: $('pNew').value }); $('dPass').close(); toast('رمز تغییر کرد'); }
  catch (err) { $('pErr').textContent = err.message; }
});
$('btnOut').addEventListener('click', async () => { await fetch('/api/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); location.href = '/login'; });

// ---------- refresh loop ----------
let busy = false;
async function refresh() {
  if (busy) return; busy = true;
  try {
    const [s, l] = await Promise.all([api('/api/stats'), api('/api/links')]);
    renderStats(s);
    if (!document.querySelector('dialog[open]')) renderLinks(l);
  } catch (e) { if (e.message !== 'auth') console.error(e); } finally { busy = false; }
}
refresh(); setInterval(refresh, 3000); window.addEventListener('resize', refresh);

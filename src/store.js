'use strict';
// JSON file persistence (atomic writes, debounced) + in-memory link registry.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const GB = 1024 ** 3;

function pickDir() {
  const want = process.env.DATA_DIR || '/data';
  for (const d of [want, path.join(process.cwd(), 'data')]) {
    try { fs.mkdirSync(d, { recursive: true }); fs.accessSync(d, fs.constants.W_OK); return d; } catch {}
  }
  throw new Error('No writable data directory (set DATA_DIR)');
}

class Store {
  constructor() {
    this.dir = pickDir();
    this.file = path.join(this.dir, 'arses.json');
    this.timer = null;
    this.data = { version: 1, secret: null, admin: null, settings: {}, links: {} };
    this.load();
  }

  load() {
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      this.data = { ...this.data, ...raw, settings: { ...raw.settings }, links: raw.links || {} };
    } catch (e) {
      if (e.code !== 'ENOENT') {                      // keep a copy of a corrupt file instead of overwriting it
        try { fs.copyFileSync(this.file, this.file + '.corrupt-' + Date.now()); } catch {}
        console.error('[store] could not parse data file, starting fresh:', e.message);
      }
    }
    if (!this.data.secret) this.data.secret = crypto.randomBytes(32).toString('hex');
    const s = this.data.settings;
    if (!s.vlessPath) s.vlessPath = '/' + crypto.randomBytes(6).toString('hex');
    if (!s.trojanPath) s.trojanPath = '/' + crypto.randomBytes(6).toString('hex');
    if (!s.name) s.name = 'آرسس';
    this.saveNow();
  }

  saveSoon() {
    if (this.timer) return;
    this.timer = setTimeout(() => { this.timer = null; this.saveNow(); }, 3000);
    this.timer.unref();
  }

  saveNow() {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    const tmp = this.file + '.tmp';
    try {
      fs.writeFileSync(tmp, JSON.stringify(this.data), { mode: 0o600 });
      fs.renameSync(tmp, this.file);
    } catch (e) { console.error('[store] save failed:', e.message); }
  }

  // ---- links ----
  list() { return Object.values(this.data.links); }
  get(id) { return this.data.links[id] || null; }
  byUuid(uuid) { return this.list().find((l) => l.uuid === uuid) || null; }

  create({ name, quotaGB = 0, expiryDays = 0 }) {
    const id = crypto.randomBytes(4).toString('hex');
    const link = {
      id, uuid: crypto.randomUUID(), name: String(name || 'link').slice(0, 60),
      enabled: true, createdAt: Date.now(),
      expiresAt: expiryDays > 0 ? Date.now() + expiryDays * 86400000 : 0,
      quotaBytes: quotaGB > 0 ? Math.round(quotaGB * GB) : 0,
      up: 0, down: 0, lastSeen: 0,
    };
    this.data.links[id] = link;
    this.saveSoon();
    return link;
  }

  update(id, patch) {
    const l = this.get(id);
    if (!l) return null;
    if (typeof patch.name === 'string' && patch.name.trim()) l.name = patch.name.trim().slice(0, 60);
    if (typeof patch.enabled === 'boolean') l.enabled = patch.enabled;
    if (patch.quotaGB !== undefined) l.quotaBytes = patch.quotaGB > 0 ? Math.round(patch.quotaGB * GB) : 0;
    if (patch.expiryDays !== undefined) l.expiresAt = patch.expiryDays > 0 ? Date.now() + patch.expiryDays * 86400000 : 0;
    this.saveSoon();
    return l;
  }

  resetUsage(id) {
    const l = this.get(id);
    if (!l) return null;
    l.up = 0; l.down = 0;
    this.saveSoon();
    return l;
  }

  remove(id) { const ok = delete this.data.links[id]; this.saveSoon(); return ok; }

  // Reason a link may not carry traffic, or null when it is usable.
  blockReason(l) {
    if (!l.enabled) return 'disabled';
    if (l.expiresAt && Date.now() >= l.expiresAt) return 'expired';
    if (l.quotaBytes && l.up + l.down >= l.quotaBytes) return 'quota';
    return null;
  }
}

module.exports = { Store, GB };

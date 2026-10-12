'use strict';
const crypto = require('crypto');

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 32);
  return salt.toString('hex') + ':' + h.toString('hex');
}
function verifyPassword(pw, stored) {
  try {
    const [s, h] = stored.split(':');
    const calc = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 32);
    return crypto.timingSafeEqual(calc, Buffer.from(h, 'hex'));
  } catch { return false; }
}

const b64u = (b) => Buffer.from(b).toString('base64url');

class Auth {
  constructor(store) {
    this.store = store;
    this.fails = new Map();                       // ip -> {n, reset}
    this.bootstrapAdmin();
    setInterval(() => { const now = Date.now(); for (const [k, v] of this.fails) if (v.reset < now) this.fails.delete(k); }, 60000).unref();
  }

  bootstrapAdmin() {
    const d = this.store.data;
    const envUser = (process.env.ADMIN_USER || '').trim();
    const envPass = process.env.ADMIN_PASSWORD || '';
    if (!d.admin) {
      const pass = envPass || '4320';
      d.admin = { user: envUser || 'admin', hash: hashPassword(pass), epoch: 1 };
      if (!envPass) console.log(`[auth] first run - default admin login: ${d.admin.user} / ${pass}  (change it in the panel)`);
      this.store.saveNow();
    } else if (envPass && !verifyPassword(envPass, d.admin.hash)) {
      // The env var is the recovery path: changing it resets the password and signs everyone out.
      d.admin.hash = hashPassword(envPass); d.admin.epoch++;
      if (envUser) d.admin.user = envUser;
      this.store.saveNow();
      console.log('[auth] admin password reset from ADMIN_PASSWORD');
    }
  }

  tooManyFailures(ip) { const f = this.fails.get(ip); return !!f && f.n >= 8 && f.reset > Date.now(); }
  recordFailure(ip) {
    const f = this.fails.get(ip);
    if (!f || f.reset < Date.now()) this.fails.set(ip, { n: 1, reset: Date.now() + 10 * 60000 });
    else f.n++;
  }
  clearFailures(ip) { this.fails.delete(ip); }

  checkLogin(user, pass) {
    const a = this.store.data.admin;
    const userOk = crypto.timingSafeEqual(
      crypto.createHash('sha256').update(String(user)).digest(),
      crypto.createHash('sha256').update(a.user).digest());
    const passOk = verifyPassword(String(pass), a.hash);   // always run scrypt: constant-ish timing
    return userOk && passOk;
  }

  changePassword(current, next) {
    const a = this.store.data.admin;
    if (!verifyPassword(String(current), a.hash)) return false;
    a.hash = hashPassword(next); a.epoch++;
    this.store.saveNow();
    return true;
  }

  _sig(payload) { return crypto.createHmac('sha256', this.store.data.secret).update(payload).digest('base64url'); }

  makeSession() {
    const a = this.store.data.admin;
    const payload = b64u(JSON.stringify({ u: a.user, e: a.epoch, x: Date.now() + 7 * 86400000 }));
    return payload + '.' + this._sig(payload);
  }

  readSession(cookieHeader) {
    const m = /(?:^|;\s*)arses_sid=([^;]+)/.exec(cookieHeader || '');
    if (!m) return null;
    const [payload, sig] = m[1].split('.');
    if (!payload || !sig) return null;
    const want = this._sig(payload);
    if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
    try {
      const p = JSON.parse(Buffer.from(payload, 'base64url').toString());
      const a = this.store.data.admin;
      if (p.x < Date.now() || p.e !== a.epoch || p.u !== a.user) return null;
      return p;
    } catch { return null; }
  }
}

module.exports = { Auth };

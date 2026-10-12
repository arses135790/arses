'use strict';
// Minimal RFC 6455 WebSocket server side (no dependencies).
const crypto = require('crypto');
const { EventEmitter } = require('events');

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

class WSConn extends EventEmitter {
  constructor(socket, maxPayload) {
    super();
    this.socket = socket;
    this.maxPayload = maxPayload;
    this.buf = Buffer.alloc(0);
    this.frag = [];
    this.fragSize = 0;
    this.fragBinary = false;
    this.closed = false;
    socket.setNoDelay(true);
    socket.on('data', (d) => this._onData(d));
    socket.on('drain', () => this.emit('drain'));
    socket.on('close', () => this._finish());
    socket.on('error', () => this._finish());
  }

  _finish() {
    if (this.closed) return;
    this.closed = true;
    this.emit('close');
  }

  _onData(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    while (!this.closed) {
      const b = this.buf;
      if (b.length < 2) return;
      const fin = (b[0] & 0x80) !== 0;
      const opcode = b[0] & 0x0f;
      const masked = (b[1] & 0x80) !== 0;
      let len = b[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (b.length < 4) return;
        len = b.readUInt16BE(2); off = 4;
      } else if (len === 127) {
        if (b.length < 10) return;
        const hi = b.readUInt32BE(2), lo = b.readUInt32BE(6);
        if (hi !== 0) return this.terminate(1009);
        len = lo; off = 10;
      }
      if (!masked) return this.terminate(1002);          // client frames must be masked
      if (len > this.maxPayload) return this.terminate(1009);
      if (b.length < off + 4 + len) return;
      const mask = b.subarray(off, off + 4);
      const payload = Buffer.allocUnsafe(len);
      const src = b.subarray(off + 4, off + 4 + len);
      for (let i = 0; i < len; i++) payload[i] = src[i] ^ mask[i & 3];
      this.buf = b.subarray(off + 4 + len);
      this._frame(fin, opcode, payload);
    }
  }

  _frame(fin, opcode, payload) {
    if (opcode >= 0x8) {                                   // control frames
      if (!fin || payload.length > 125) return this.terminate(1002);
      if (opcode === 0x8) { this._sendFrame(0x8, payload.subarray(0, 2)); return this._end(); }
      if (opcode === 0x9) return void this._sendFrame(0xA, payload);
      return;                                              // pong
    }
    if (opcode === 0x0) {                                  // continuation
      if (!this.frag.length) return this.terminate(1002);
    } else if (opcode === 0x1 || opcode === 0x2) {
      if (this.frag.length) return this.terminate(1002);
      this.fragBinary = opcode === 0x2;
    } else return this.terminate(1002);
    this.fragSize += payload.length;
    if (this.fragSize > this.maxPayload) return this.terminate(1009);
    this.frag.push(payload);
    if (fin) {
      const msg = this.frag.length === 1 ? this.frag[0] : Buffer.concat(this.frag);
      this.frag = []; this.fragSize = 0;
      this.emit('message', msg, this.fragBinary);
    }
  }

  _sendFrame(opcode, payload) {
    if (this.closed || this.socket.destroyed) return false;
    const len = payload.length;
    let head;
    if (len < 126) { head = Buffer.alloc(2); head[1] = len; }
    else if (len < 65536) { head = Buffer.alloc(4); head[1] = 126; head.writeUInt16BE(len, 2); }
    else { head = Buffer.alloc(10); head[1] = 127; head.writeUInt32BE(0, 2); head.writeUInt32BE(len, 6); }
    head[0] = 0x80 | opcode;
    this.socket.cork();
    this.socket.write(head);
    const ok = this.socket.write(payload);
    this.socket.uncork();
    return ok;
  }

  send(data) { return this._sendFrame(0x2, data); }       // returns false when backpressured
  pause() { this.socket.pause(); }
  resume() { this.socket.resume(); }

  close(code = 1000) {
    if (this.closed) return;
    const p = Buffer.alloc(2); p.writeUInt16BE(code);
    this._sendFrame(0x8, p);
    this._end();
  }
  terminate(code = 1002) { this.close(code); }
  _end() { try { this.socket.end(); } catch {} setTimeout(() => this.socket.destroy(), 1500).unref(); }
}

// Returns a WSConn after completing the handshake, or null (and answers with an HTTP error).
function accept(req, socket, head, { maxPayload = 4 * 1024 * 1024 } = {}) {
  const key = req.headers['sec-websocket-key'];
  const upgrade = String(req.headers.upgrade || '').toLowerCase();
  if (upgrade !== 'websocket' || !key || req.headers['sec-websocket-version'] !== '13') {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return null;
  }
  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  const lines = ['HTTP/1.1 101 Switching Protocols', 'Upgrade: websocket', 'Connection: Upgrade', `Sec-WebSocket-Accept: ${accept}`];
  // Early-data clients carry the first payload in this header; echo it as the "chosen" subprotocol.
  const proto = req.headers['sec-websocket-protocol'];
  let early = null;
  if (proto && /^[A-Za-z0-9_\-=]+$/.test(proto)) {
    lines.push(`Sec-WebSocket-Protocol: ${proto}`);
    try { early = Buffer.from(proto.replace(/-/g, '+').replace(/_/g, '/'), 'base64'); } catch { early = null; }
  }
  socket.write(lines.join('\r\n') + '\r\n\r\n');
  const ws = new WSConn(socket, maxPayload);
  if (head && head.length) ws._onData(head);
  ws.earlyData = early && early.length ? early : null;
  return ws;
}

module.exports = { accept };

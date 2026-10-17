/*
 * Kontaq — dashboard WhatsApp Cloud API resmi (Meta).
 * Satu file backend: konfigurasi, database JSON (MVP), autentikasi, Meta Graph API,
 * webhook, inbox real-time (Socket.IO), template, kontak, campaign, panggilan, audit log.
 *
 * Bagian:
 *   1. Konfigurasi & utilitas
 *   2. Database JSON
 *   3. Autentikasi & akses
 *   4. Meta Graph API
 *   5. Domain: kontak, percakapan, pesan
 *   6. Webhook (+ 6b. notifikasi WA via gateway)
 *   7. Routes API
 *   8. Campaign worker
 *   9. Socket.IO & start
 */
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');
const crypto = require('crypto');
const express = require('express');
const axios = require('axios');
const multer = require('multer');
const { Server } = require('socket.io');

/* ───────────────────────── 1. Konfigurasi & utilitas ───────────────────────── */

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const SERVICE_WINDOW_MS = 24 * 60 * 60 * 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const COOKIE_NAME = 'kq_session';
const CAMPAIGN_RATE = Math.max(1, Math.min(80, Number(process.env.CAMPAIGN_RATE_PER_SEC || 10)));

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Rahasia sesi/enkripsi. Bila .env kosong, dibuat sekali dan disimpan di data/ (jangan di-commit).
const SECRET = (() => {
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 32) return process.env.SESSION_SECRET;
  const f = path.join(DATA_DIR, 'secret.key');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(48).toString('hex'), { mode: 0o600 });
  console.warn('[kontaq] SESSION_SECRET kosong/pendek — memakai data/secret.key. Isi SESSION_SECRET di .env untuk produksi.');
  return fs.readFileSync(f, 'utf8').trim();
})();
const ENC_KEY = crypto.createHash('sha256').update('kontaq-enc:' + SECRET).digest();

class HttpError extends Error {
  constructor(status, message, meta) { super(message); this.status = status; this.meta = meta; }
}
const uid = (p = '') => p + crypto.randomBytes(9).toString('base64url');
const now = () => Date.now();
// SDP tidak boleh di-trim: setiap baris (termasuk yang terakhir) wajib diakhiri CRLF (RFC 8866)
const sdpParam = (v) => (typeof v === 'string' && v.length <= 20000 && v.startsWith('v=0') ? v.replace(/\r?\n/g, '\r\n').replace(/(\r\n)*$/, '\r\n') : '');
const str = (v, max = 4096) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const normPhone = (v) => String(v || '').replace(/[^\d]/g, '');
const validPhone = (p) => /^\d{8,15}$/.test(p);

function encrypt(plain) {
  if (!plain) return '';
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), enc].map((b) => b.toString('base64')).join('.');
}
function decrypt(blob) {
  if (!blob) return '';
  try {
    const [iv, tag, enc] = blob.split('.').map((s) => Buffer.from(s, 'base64'));
    const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
  } catch { return ''; }
}
const mask = (s) => (s ? '••••' + s.slice(-4) : '');

function parseCsv(text) {
  const rows = []; let row = []; let cur = ''; let q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) {
      if (ch === '"' && text[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') q = false;
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',' || ch === ';') { row.push(cur); cur = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(cur); rows.push(row); row = []; cur = '';
    } else cur += ch;
  }
  if (cur || row.length) { row.push(cur); rows.push(row); }
  return rows.filter((r) => r.some((c) => c.trim()));
}
const csvCell = (v) => {
  const s = v == null ? '' : String(v);
  return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

/* ───────────────────────── 2. Database JSON (MVP) ─────────────────────────
 * Cocok untuk satu instance/tim kecil. Untuk multiuser skala produksi, ganti lapisan ini ke MySQL
 * (struktur koleksi di bawah sudah setara tabel: users, contacts, conversations, messages, ...).
 */
const EMPTY_DB = {
  settings: {}, users: [], contacts: [], conversations: [], messages: [],
  templates: [], templatesSyncedAt: 0, campaigns: [], calls: [], audit: [], avatars: {}, autoReply: null, arMedia: {}, costs: null, sendLog: [],
  flows: [], flowRuns: [], groups: [], csat: null, waFlows: [], flowSubmissions: [], stickers: [],
};
let db;
try { db = { ...EMPTY_DB, ...JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) }; }
catch { db = structuredClone(EMPTY_DB); }

let saveTimer = null;
function flushDb() {
  clearTimeout(saveTimer); saveTimer = null;
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}
function save() { if (!saveTimer) saveTimer = setTimeout(flushDb, 250); }

// Indeks in-memory
const idx = { wamid: new Map(), contactByPhone: new Map(), convByContact: new Map() };
function reindex() {
  idx.wamid.clear(); idx.contactByPhone.clear(); idx.convByContact.clear();
  db.messages.forEach((m) => m.wamid && idx.wamid.set(m.wamid, m));
  db.contacts.forEach((c) => idx.contactByPhone.set(c.phone, c));
  db.conversations.forEach((c) => idx.convByContact.set(c.contactId, c));
}
reindex();
const byId = (coll, id) => db[coll].find((x) => x.id === id);

function audit(req, action, detail = '') {
  db.audit.push({ id: uid('a_'), at: now(), userId: req?.user?.id || null, userName: req?.user?.name || 'sistem', action, detail: String(detail).slice(0, 500), ip: req?.ip || '' });
  if (db.audit.length > 5000) db.audit.splice(0, db.audit.length - 5000);
  save();
}

/* ───────────────────────── 3. Autentikasi & akses ───────────────────────── */

function hashPassword(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') };
}
function checkPassword(user, pw) {
  const h = crypto.scryptSync(String(pw), user.salt, 64);
  return crypto.timingSafeEqual(h, Buffer.from(user.hash, 'hex'));
}
function validatePassword(pw) {
  if (typeof pw !== 'string' || pw.length < 10) throw new HttpError(400, 'Kata sandi minimal 10 karakter.');
}
const sign = (data) => crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
function makeToken(user) {
  const exp = now() + SESSION_TTL_MS;
  const data = `${user.id}.${exp}.${user.sessionVersion || 0}`;
  return `${data}.${sign(data)}`;
}
function userFromToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 4) return null;
  const [id, exp, ver, sig] = parts;
  const expected = sign(`${id}.${exp}.${ver}`);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  if (Number(exp) < now()) return null;
  const user = byId('users', id);
  if (!user || !user.active || String(user.sessionVersion || 0) !== ver) return null;
  return user;
}
function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map((c) => c.trim().split('=')).filter((p) => p[0])
    .map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));
}
function setSessionCookie(res, token, maxAge = SESSION_TTL_MS) {
  res.cookie(COOKIE_NAME, token, { httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true', maxAge, path: '/' });
}
const publicUser = (u) => u && { id: u.id, name: u.name, email: u.email, role: u.role, active: u.active, createdAt: u.createdAt, lastLoginAt: u.lastLoginAt };

const loginAttempts = new Map(); // ip -> { n, until }
function loginGuard(ip) {
  const a = loginAttempts.get(ip);
  if (a && a.until > now()) throw new HttpError(429, 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.');
}
function loginFail(ip) {
  const a = loginAttempts.get(ip) || { n: 0, until: 0 };
  a.n++; if (a.n >= 8) { a.until = now() + 15 * 60 * 1000; a.n = 0; }
  loginAttempts.set(ip, a);
}

function requireAuth(req, res, next) {
  if (!req.user) return next(new HttpError(401, 'Sesi berakhir. Silakan masuk kembali.'));
  next();
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return next(new HttpError(403, 'Hanya admin yang dapat melakukan tindakan ini.'));
  next();
}
// Agen hanya boleh membuka percakapan yang ditugaskan ke dirinya atau belum ditugaskan.
function canSeeConv(user, conv) {
  return user.role === 'admin' || !conv.assignedTo || conv.assignedTo === user.id;
}
function convOr404(req) {
  const conv = byId('conversations', req.params.id);
  if (!conv || !canSeeConv(req.user, conv)) throw new HttpError(404, 'Percakapan tidak ditemukan.');
  return conv;
}

/* ───────────────────────── 4. Meta Graph API ───────────────────────── */

function meta() {
  const s = db.settings;
  return {
    graphVersion: s.graphVersion || process.env.META_GRAPH_VERSION || 'v23.0',
    phoneNumberId: s.phoneNumberId || process.env.META_PHONE_NUMBER_ID || '',
    wabaId: s.wabaId || process.env.META_WABA_ID || '',
    accessToken: decrypt(s.accessTokenEnc) || process.env.META_ACCESS_TOKEN || '',
    appSecret: decrypt(s.appSecretEnc) || process.env.META_APP_SECRET || '',
    verifyToken: s.verifyToken || process.env.META_VERIFY_TOKEN || '',
  };
}
function metaError(e) {
  const err = e.response?.data?.error;
  if (!err) return Object.assign(new HttpError(502, `Gagal menghubungi Meta: ${e.message}`), { httpStatus: e.response?.status || 0 });
  const details = err.error_data?.details ? ` — ${err.error_data.details}` : '';
  const out = new HttpError(e.response.status >= 500 ? 502 : 400, `Meta: ${err.message}${details} (kode ${err.code}${err.error_subcode ? '/' + err.error_subcode : ''})`, err);
  out.httpStatus = e.response.status; // status HTTP asli dari Graph API (untuk log pengiriman)
  return out;
}
async function graph(method, endpoint, { data, params, headers, responseType } = {}) {
  const m = meta();
  if (!m.accessToken) throw new HttpError(400, 'Koneksi Meta belum dikonfigurasi (Access Token kosong).');
  try {
    const r = await axios({
      method, url: `https://graph.facebook.com/${m.graphVersion}/${endpoint}`,
      data, params, responseType, timeout: 30000,
      headers: { Authorization: `Bearer ${m.accessToken}`, ...headers },
      maxBodyLength: Infinity, maxContentLength: Infinity,
    });
    return r.data;
  } catch (e) { throw metaError(e); }
}
function needPhone() { const m = meta(); if (!m.phoneNumberId) throw new HttpError(400, 'Phone Number ID belum diisi.'); return m.phoneNumberId; }
function needWaba() { const m = meta(); if (!m.wabaId) throw new HttpError(400, 'WABA ID belum diisi.'); return m.wabaId; }

async function uploadMedia(file) {
  const fd = new FormData();
  fd.append('messaging_product', 'whatsapp');
  fd.append('type', file.mimetype);
  fd.append('file', new Blob([file.buffer], { type: file.mimetype }), file.originalname);
  const r = await graph('post', `${needPhone()}/media`, { data: fd });
  return r.id;
}

/* ───────────────────────── 5. Domain: kontak, percakapan, pesan ───────────────────────── */

function getOrCreateContact(phone, name) {
  let c = idx.contactByPhone.get(phone);
  if (!c) {
    c = { id: uid('c_'), phone, name: name || '', waName: name || '', labels: [], notes: '', optIn: false, createdAt: now(), updatedAt: now() };
    db.contacts.push(c); idx.contactByPhone.set(phone, c);
  } else if (name && c.waName !== name) {
    c.waName = name; if (!c.name) c.name = name; c.updatedAt = now();
  }
  return c;
}
function getOrCreateConv(contact) {
  let conv = idx.convByContact.get(contact.id);
  if (!conv) {
    conv = { id: uid('v_'), contactId: contact.id, status: 'open', assignedTo: null, unread: 0, lastMessageAt: 0, lastInboundAt: 0, preview: '', notes: [], createdAt: now() };
    db.conversations.push(conv); idx.convByContact.set(contact.id, conv);
  }
  return conv;
}
const callPermissionActive = (c) => c.callPermission?.status === 'accept' && (c.callPermission.permanent || !c.callPermission.expiresAt || c.callPermission.expiresAt > now());
const windowOpen = (conv) => conv.lastInboundAt && now() - conv.lastInboundAt < SERVICE_WINDOW_MS;

function previewOf(m) {
  const c = m.content || {};
  switch (m.type) {
    case 'text': return c.body;
    case 'image': return '📷 ' + (c.caption || 'Gambar');
    case 'video': return '🎬 ' + (c.caption || 'Video');
    case 'audio': return c.voice ? '🎤 Pesan suara' : '🎵 Audio';
    case 'document': return '📄 ' + (c.filename || 'Dokumen');
    case 'sticker': return '🏷️ Stiker';
    case 'location': return '📍 ' + (c.name || 'Lokasi');
    case 'interactive': return (c.kind === 'flow' ? '📋 ' : '☰ ') + (c.body || 'Pesan interaktif');
    case 'interactive_reply': return '↩ ' + c.title;
    case 'flow_reply': return '📋 Formulir dikirim';
    case 'call_permission': return c.response === 'accept' ? '📞 Bersedia ditelepon balik' : '📞 Menolak ditelepon';
    case 'button': return '↩ ' + c.text;
    case 'template': return '▤ Template: ' + c.name;
    case 'contacts': return '👤 Kontak';
    default: return c.body || m.type;
  }
}

function serializeConv(conv) {
  const contact = byId('contacts', conv.contactId) || {};
  const agent = conv.assignedTo ? byId('users', conv.assignedTo) : null;
  return {
    ...conv, contact, assignedName: agent?.name || null,
    windowOpen: !!windowOpen(conv), windowExpiresAt: conv.lastInboundAt ? conv.lastInboundAt + SERVICE_WINDOW_MS : 0,
    csat: csatPublic(csatOf(conv)),
  };
}

// Emit hanya ke pengguna yang berhak melihat percakapan
function emitConv(conv, event, payload) {
  if (!io) return;
  // Satu emit ke beberapa room: Socket.IO mengirim sekali per socket meski socket ada di beberapa room
  io.to(['admins', conv.assignedTo ? 'user:' + conv.assignedTo : 'agents']).emit(event, payload);
}
function touchConv(conv, msg) {
  conv.lastMessageAt = msg.timestamp;
  conv.preview = String(previewOf(msg) || '').slice(0, 140);
  if (msg.direction === 'in') {
    conv.lastInboundAt = msg.timestamp; conv.unread = (conv.unread || 0) + 1;
    if (conv.status === 'closed') conv.status = 'open';
  }
}
function addMessage(conv, data) {
  const msg = { id: uid('m_'), conversationId: conv.id, status: data.direction === 'out' ? 'pending' : 'received', timestamp: now(), ...data };
  db.messages.push(msg);
  if (msg.wamid) idx.wamid.set(msg.wamid, msg);
  touchConv(conv, msg);
  // Pesan WhatsApp Flow (interaktif atau template bertombol FLOW): catat pengiriman agar jawabannya dapat dicocokkan lewat flow_token
  if (msg.direction === 'out' && msg.content?.flowToken) recordFlowSend(conv, msg);
  save();
  emitConv(conv, 'message:new', { message: msg, conversation: serializeConv(conv) });
  return msg;
}

const STATUS_RANK = { pending: 0, accepted: 0.5, sent: 1, delivered: 2, read: 3, played: 3 };

// Bangun payload Meta dari input composer, dengan validasi batas resmi Cloud API.
function buildOutbound(type, b) {
  const p = {};
  switch (type) {
    case 'text': {
      const body = str(b.body, 4096);
      if (!body) throw new HttpError(400, 'Pesan kosong.');
      p.text = { body, preview_url: /https?:\/\//.test(body) };
      return { payload: p, content: { body } };
    }
    case 'image': case 'video': case 'audio': case 'document': {
      if (!b.mediaId) throw new HttpError(400, 'Media belum diunggah.');
      const obj = { id: String(b.mediaId) };
      if (type !== 'audio' && b.caption) obj.caption = str(b.caption, 1024);
      if (type === 'document' && b.filename) obj.filename = str(b.filename, 240);
      // Pesan suara: hanya untuk OGG/Opus (hasil konversi /api/media kind=voice)
      if (type === 'audio' && b.voice && /^audio\/ogg/.test(str(b.mime, 100))) obj.voice = true;
      p[type] = obj;
      const num = (v, max) => { const n = Number(v); return Number.isFinite(n) && n > 0 && n <= max ? Math.round(n * 10) / 10 : 0; };
      return { payload: p, content: { mediaId: obj.id, caption: obj.caption || '', filename: obj.filename || '', mime: str(b.mime, 100),
        voice: !!obj.voice, size: num(b.size, 200 * 1024 * 1024), duration: num(b.duration, 86400), width: num(b.width, 20000), height: num(b.height, 20000) } };
    }
    case 'sticker': {
      if (!b.mediaId) throw new HttpError(400, 'Stiker belum dipilih.');
      p.sticker = { id: String(b.mediaId) };
      return { payload: p, content: { mediaId: p.sticker.id, stickerId: str(b.stickerId, 40), animated: !!b.animated, mime: 'image/webp' } };
    }
    case 'contacts': {
      // Kartu kontak (vCard). formatted_name wajib; wa_id diisi untuk kontak WhatsApp agar penerima bisa langsung "Kirim pesan".
      const list = (Array.isArray(b.contacts) ? b.contacts : []).slice(0, 10).map((k) => {
        const name = str(k?.name, 200);
        if (!name) throw new HttpError(400, 'Nama kontak wajib diisi.');
        const [first, ...rest] = name.split(/\s+/);
        // Nomor lokal (0812…) diubah ke format internasional Indonesia (62812…)
        const phones = (Array.isArray(k.phones) ? k.phones : []).map((x) => normPhone(typeof x === 'object' ? x.phone : x)).map((d) => (d.startsWith('0') ? '62' + d.slice(1) : d)).filter(validPhone).slice(0, 5)
          .map((d) => ({ phone: '+' + d, type: 'CELL', ...(k.whatsapp ? { wa_id: d } : {}) }));
        const emails = (Array.isArray(k.emails) ? k.emails : []).map((x) => str(typeof x === 'object' ? x.email : x, 200)).filter((e) => /^\S+@\S+\.\S+$/.test(e)).slice(0, 3).map((email) => ({ email, type: 'WORK' }));
        if (!phones.length && !emails.length) throw new HttpError(400, `Kontak "${name}" belum punya nomor telepon atau email yang valid.`);
        const company = str(k.company, 200);
        return { name: { formatted_name: name, first_name: first, ...(rest.length ? { last_name: rest.join(' ') } : {}) }, phones, emails, ...(company ? { org: { company } } : {}) };
      });
      if (!list.length) throw new HttpError(400, 'Pilih minimal satu kontak.');
      p.contacts = list;
      return { payload: p, content: { contacts: list.map((k) => ({ name: k.name.formatted_name, phones: k.phones.map((x) => x.phone), emails: k.emails.map((x) => x.email), company: k.org?.company || '' })) } };
    }
    case 'location': {
      const latitude = Number(b.latitude), longitude = Number(b.longitude);
      if (!(latitude >= -90 && latitude <= 90) || !(longitude >= -180 && longitude <= 180) || b.latitude === '' || b.longitude === '') throw new HttpError(400, 'Koordinat tidak valid.');
      p.location = { latitude, longitude, name: str(b.name, 1000), address: str(b.address, 1000) };
      return { payload: p, content: p.location };
    }
    case 'buttons': {
      const body = str(b.body, 1024);
      const buttons = (Array.isArray(b.buttons) ? b.buttons : []).map((t) => str(t, 20)).filter(Boolean);
      if (!body) throw new HttpError(400, 'Isi pesan wajib diisi.');
      if (buttons.length < 1 || buttons.length > 3) throw new HttpError(400, 'Tombol balasan harus 1–3.');
      if (new Set(buttons).size !== buttons.length) throw new HttpError(400, 'Judul tombol harus unik.');
      const interactive = {
        type: 'button', body: { text: body },
        action: { buttons: buttons.map((title, i) => ({ type: 'reply', reply: { id: `btn_${i + 1}`, title } })) },
      };
      if (b.header) interactive.header = { type: 'text', text: str(b.header, 60) };
      if (b.footer) interactive.footer = { text: str(b.footer, 60) };
      p.interactive = interactive;
      return { payload: p, content: { kind: 'button', header: b.header ? str(b.header, 60) : '', body, footer: str(b.footer, 60), buttons }, type: 'interactive' };
    }
    case 'list': {
      const body = str(b.body, 4096), button = str(b.button, 20);
      const rows = (Array.isArray(b.rows) ? b.rows : []).map((r, i) => ({ id: `row_${i + 1}`, title: str(r.title, 24), description: str(r.description, 72) })).filter((r) => r.title);
      if (!body || !button) throw new HttpError(400, 'Isi pesan dan teks tombol wajib diisi.');
      if (rows.length < 1 || rows.length > 10) throw new HttpError(400, 'Daftar harus berisi 1–10 baris.');
      const interactive = {
        type: 'list', body: { text: body },
        action: { button, sections: [{ title: str(b.sectionTitle, 24) || 'Pilihan', rows: rows.map((r) => (r.description ? r : { id: r.id, title: r.title })) }] },
      };
      if (b.header) interactive.header = { type: 'text', text: str(b.header, 60) };
      if (b.footer) interactive.footer = { text: str(b.footer, 60) };
      p.interactive = interactive;
      return { payload: p, content: { kind: 'list', header: str(b.header, 60), body, footer: str(b.footer, 60), button, rows }, type: 'interactive' };
    }
    case 'flow': {
      const m = buildWaFlowMessage(b);
      return { payload: { interactive: m.interactive }, content: m.content, type: 'interactive' };
    }
    case 'call_permission_request': {
      const body = str(b.body, 1024) || 'Boleh kami menelepon Anda melalui WhatsApp untuk membantu lebih lanjut?';
      p.interactive = { type: 'call_permission_request', action: { name: 'call_permission_request' }, body: { text: body } };
      return { payload: p, content: { kind: 'call_permission_request', body }, type: 'interactive' };
    }
    default: throw new HttpError(400, 'Tipe pesan tidak didukung.');
  }
}

// Variabel template: {{1}} (positional) atau {{nama}} (named)
function templateVars(text = '') {
  return [...new Set([...String(text).matchAll(/\{\{\s*([\w]+)\s*\}\}/g)].map((m) => m[1]))];
}
function findTemplate(name, language) {
  return db.templates.find((t) => t.name === name && t.language === language);
}
// values: { header: [..] | headerMedia: url, body: [..] } dengan placeholder {{name}}/{{phone}} diganti dari kontak
function buildTemplateComponents(tpl, values = {}, contact = {}) {
  const fill = (v) => String(v ?? '').replace(/\{\{\s*(name|phone)\s*\}\}/g, (_, k) => (k === 'name' ? contact.name || contact.waName || '' : contact.phone || ''));
  const named = tpl.parameter_format === 'NAMED';
  const comps = [];
  const header = (tpl.components || []).find((c) => c.type === 'HEADER');
  const body = (tpl.components || []).find((c) => c.type === 'BODY');
  const param = (name, v) => {
    const text = fill(v);
    if (!text) throw new HttpError(400, `Variabel {{${name}}} belum diisi.`);
    return named ? { type: 'text', parameter_name: name, text } : { type: 'text', text };
  };
  if (header) {
    if (header.format === 'TEXT') {
      const vars = templateVars(header.text);
      if (vars.length) comps.push({ type: 'header', parameters: vars.map((v, i) => param(v, (values.header || [])[i])) });
    } else if (['IMAGE', 'VIDEO', 'DOCUMENT'].includes(header.format)) {
      const link = str(values.headerMedia, 2000);
      if (!/^https:\/\//.test(link)) throw new HttpError(400, `Template memerlukan URL HTTPS untuk header ${header.format.toLowerCase()}.`);
      const k = header.format.toLowerCase();
      comps.push({ type: 'header', parameters: [{ type: k, [k]: { link } }] });
    }
  }
  if (body) {
    const vars = templateVars(body.text);
    if (vars.length) comps.push({ type: 'body', parameters: vars.map((v, i) => param(v, (values.body || [])[i])) });
  }
  // Tombol URL dinamis (mis. template undangan grup https://chat.whatsapp.com/{{1}}): values.buttonUrl[index] = akhiran URL
  const buttons = (tpl.components || []).find((c) => c.type === 'BUTTONS');
  (buttons?.buttons || []).forEach((btn, i) => {
    // Tombol FLOW: setiap pengiriman mendapat flow_token sendiri agar jawaban formulir dapat dicocokkan
    if (btn.type === 'FLOW') {
      comps.push({ type: 'button', sub_type: 'flow', index: String(i), parameters: [{ type: 'action', action: { flow_token: newFlowToken() } }] });
      return;
    }
    if (btn.type !== 'URL' || !/\{\{/.test(btn.url || '')) return;
    const text = fill((values.buttonUrl || [])[i]);
    if (!text) throw new HttpError(400, `Tombol URL "${btn.text}" memerlukan nilai variabel.`);
    comps.push({ type: 'button', sub_type: 'url', index: String(i), parameters: [{ type: 'text', text }] });
  });
  return comps;
}
// Info WhatsApp Flow dari komponen template yang sudah dibangun (tombol FLOW)
function templateFlowInfo(tpl, comps) {
  const c = comps.find((x) => x.type === 'button' && x.sub_type === 'flow');
  if (!c) return null;
  const btn = (tpl.components || []).find((x) => x.type === 'BUTTONS')?.buttons?.[Number(c.index)] || {};
  const f = wafById(btn.flow_id);
  return { flowToken: c.parameters[0].action.flow_token, flowId: btn.flow_id ? String(btn.flow_id) : null, flowName: f?.name || btn.text || 'Flow' };
}
function renderTemplateText(tpl, comps) {
  const body = (tpl.components || []).find((c) => c.type === 'BODY');
  const bodyParams = comps.find((c) => c.type === 'body')?.parameters || [];
  let i = 0;
  return String(body?.text || '').replace(/\{\{\s*([\w]+)\s*\}\}/g, () => bodyParams[i++]?.text ?? '');
}

async function sendTemplateTo(contact, tpl, values, extra = {}, ctx = {}) {
  const components = buildTemplateComponents(tpl, values, contact);
  const payload = { messaging_product: 'whatsapp', recipient_type: 'individual', to: contact.phone, type: 'template', template: { name: tpl.name, language: { code: tpl.language } } };
  if (components.length) payload.template.components = components;
  const conv = getOrCreateConv(contact);
  const r = await sendToMeta(payload, { source: 'inbox', contact, conversation: conv, template: tpl, userId: extra.userId, userName: extra.userName, ...ctx });
  // 'accepted' = Meta menerima request; sent/delivered/read hanya dari webhook status
  const msg = addMessage(conv, {
    direction: 'out', type: 'template', wamid: r.messages?.[0]?.id, status: 'accepted',
    content: { name: tpl.name, language: tpl.language, body: renderTemplateText(tpl, components), ...templateFlowInfo(tpl, components) }, ...extra,
  });
  return msg;
}

/* ───────────────────────── 5b. Log pengiriman pesan (Cloud API) ─────────────────────────
 * Setiap POST /{phone-number-id}/messages dari Kontaq (inbox, template, campaign, auto reply) dicatat di db.sendLog,
 * berhasil maupun gagal. Status dipisah per tahap:
 *   1. request  — HTTP ke Graph API berhasil/gagal
 *   2. accepted — Meta mengembalikan message ID (belum berarti terkirim)
 *   3. sent / delivered / read / failed — hanya dari webhook status, dihubungkan lewat message ID (wamid)
 * Status webhook untuk wamid yang tidak dikenal (dikirim di luar Kontaq dengan nomor yang sama) dicatat sebagai sumber "external".
 * Access token, App Secret, dan kredensial lain tidak pernah masuk ke log.
 */
const SEND_LOG_MAX = 20000;
const logByWamid = new Map();
db.sendLog.forEach((e) => e.wamid && logByWamid.set(e.wamid, e));
const DELIVERY_RANK = { accepted: 0, sent: 1, delivered: 2, read: 3, played: 3 };

function pushLog(entry) {
  db.sendLog.push(entry);
  if (entry.wamid) logByWamid.set(entry.wamid, entry);
  if (db.sendLog.length > SEND_LOG_MAX) {
    for (const old of db.sendLog.splice(0, db.sendLog.length - SEND_LOG_MAX)) if (old.wamid) logByWamid.delete(old.wamid);
  }
  save();
  return entry;
}

// Ringkasan isi pesan untuk kolom "Isi pesan" (tanpa kredensial; nomor penerima disamarkan di payload).
function payloadSummary(p) {
  const it = p.interactive;
  switch (p.type) {
    case 'text': return p.text?.body || '';
    case 'template': return p.template?.name || '';
    case 'image': case 'video': case 'audio': case 'document': case 'sticker': return p[p.type]?.caption || p[p.type]?.filename || '';
    case 'location': return p.location?.name || `${p.location?.latitude}, ${p.location?.longitude}`;
    case 'interactive': return it?.body?.text || '';
    default: return '';
  }
}
function payloadKind(p) {
  if (p.type !== 'interactive') return p.type || 'unknown';
  return { button: 'buttons', list: 'list', flow: 'flow', call_permission_request: 'call_permission' }[p.interactive?.type] || 'interactive';
}
const maskPhone = (p) => (p && p.length > 6 ? p.slice(0, 4) + '•'.repeat(p.length - 6) + p.slice(-2) : p || '');
function redactPayload(p) {
  const copy = structuredClone(p);
  if (copy.to) copy.to = maskPhone(String(copy.to));
  return copy;
}

/**
 * Kirim pesan ke Cloud API dan catat hasilnya. ctx: { source, contact, conversation, userId, userName, campaign, template }
 * Melempar error yang sama seperti graph() bila gagal (setelah dicatat).
 */
async function sendToMeta(payload, ctx = {}) {
  const m = meta();
  const entry = {
    id: uid('l_'), at: now(), source: ctx.source || 'inbox', userId: ctx.userId || null, userName: ctx.userName || '',
    campaignId: ctx.campaign?.id || null, campaignName: ctx.campaign?.name || '',
    contactId: ctx.contact?.id || null, conversationId: ctx.conversation?.id || null, to: String(payload.to || ''),
    type: payloadKind(payload), summary: String(payloadSummary(payload) || '').slice(0, 300),
    templateName: payload.template?.name || '', templateLanguage: payload.template?.language?.code || '',
    templateCategory: ctx.template?.category || '', phoneNumberId: m.phoneNumberId, wabaId: m.wabaId, graphVersion: m.graphVersion,
    request: redactPayload(payload), ok: false, http: null, response: null, error: null, wamid: null, statuses: [],
  };
  const started = Date.now();
  try {
    const r = await graph('post', `${needPhone()}/messages`, { data: payload });
    const info = r.messages?.[0] || {};
    Object.assign(entry, {
      ok: true, wamid: info.id || null, http: { status: 200, ms: Date.now() - started },
      // message_status: accepted | held_for_quality_assessment | paused (Meta). Bukan bukti pesan sampai ke pelanggan.
      response: { messageStatus: info.message_status || 'accepted', waId: r.contacts?.[0]?.wa_id || null },
    });
    pushLog(entry);
    return r;
  } catch (e) {
    Object.assign(entry, {
      http: { status: e.httpStatus || 0, ms: Date.now() - started },
      error: { message: e.message, code: e.meta?.code ?? null, subcode: e.meta?.error_subcode ?? null, type: e.meta?.type || null, fbtraceId: e.meta?.fbtrace_id || null, details: e.meta?.error_data?.details || null },
    });
    pushLog(entry);
    throw e;
  }
}

/** Catat status webhook (idempoten: status+timestamp yang sama diabaikan). Mengembalikan true bila ada perubahan. */
function recordStatus(target, s) {
  const at = Number(s.timestamp) * 1000 || now();
  target.statusHistory = target.statusHistory || [];
  if (target.statusHistory.some((h) => h.status === s.status && h.at === at)) return false;
  const h = { status: s.status, at };
  if (s.errors?.length) h.errors = s.errors.map((e) => ({ code: e.code, title: e.title || e.message, details: e.error_data?.details || '' }));
  target.statusHistory.push(h);
  target.statusHistory.sort((a, b) => a.at - b.at);
  const key = { sent: 'sentAt', delivered: 'deliveredAt', read: 'readAt', played: 'readAt', failed: 'failedAt' }[s.status];
  if (key && !target[key]) target[key] = at;
  return true;
}

/** Status pesan untuk log: hanya status webhook dianggap "terkirim"; tanpa webhook = "accepted" (diterima Meta). */
function deliveryState(entry, msg) {
  if (!entry.ok) return 'failed';
  const hist = (msg || entry).statusHistory || [];
  if (hist.some((h) => h.status === 'failed') && !hist.some((h) => h.status === 'read' || h.status === 'played')) return 'failed';
  let best = 'accepted';
  for (const h of hist) if ((DELIVERY_RANK[h.status] ?? -1) > DELIVERY_RANK[best]) best = h.status === 'played' ? 'read' : h.status;
  return best;
}

/** Estimasi biaya: pricing dari webhook × tarif per kategori yang diisi admin di Cost Monitor. */
function estimateCost(pricing) {
  if (!pricing) return { known: false };
  if (!pricing.billable) return { known: true, billable: false, amount: 0, category: pricing.category };
  const rate = Number(costCfg().settings.rates?.[pricing.category]);
  return { known: Number.isFinite(rate) && rate > 0, billable: true, amount: rate > 0 ? rate : null, category: pricing.category };
}

// Isi log dari pesan keluar yang tercatat sebelum fitur log ada (sekali saja; data request/respons tidak tersedia).
if (!db.sendLogBackfilled) {
  for (const msg of db.messages) {
    if (msg.direction !== 'out' || (msg.wamid && logByWamid.has(msg.wamid))) continue;
    const conv = byId('conversations', msg.conversationId);
    const contact = conv ? byId('contacts', conv.contactId) : null;
    const camp = msg.campaignId ? byId('campaigns', msg.campaignId) : null;
    pushLog({
      id: uid('l_'), at: msg.timestamp, source: msg.campaignId ? 'campaign' : msg.auto ? 'auto_reply' : 'inbox',
      userId: msg.userId || null, userName: msg.userName || '', campaignId: msg.campaignId || null, campaignName: camp?.name || '',
      contactId: contact?.id || null, conversationId: conv?.id || null, to: contact?.phone || '',
      type: msg.type === 'interactive' ? ({ button: 'buttons', list: 'list', call_permission_request: 'call_permission' }[msg.content?.kind] || 'interactive') : msg.type,
      summary: String(msg.type === 'template' ? msg.content?.name : previewOf(msg) || '').slice(0, 300),
      templateName: msg.type === 'template' ? msg.content?.name || '' : '', templateLanguage: msg.content?.language || '', templateCategory: '',
      phoneNumberId: meta().phoneNumberId, wabaId: meta().wabaId, graphVersion: '',
      request: null, ok: !!msg.wamid, http: null, response: msg.wamid ? { messageStatus: 'accepted' } : null,
      error: msg.wamid ? null : { message: msg.error || 'Tidak ada message ID' }, wamid: msg.wamid || null, statuses: [], backfilled: true,
    });
    // Status lama hanya menyimpan status terakhir; jadikan satu entri riwayat agar tetap terbaca.
    if (msg.status && msg.status !== 'pending' && msg.status !== 'sent' && !msg.statusHistory) msg.statusHistory = [{ status: msg.status, at: msg.statusAt || msg.timestamp }];
  }
  db.sendLog.sort((a, b) => a.at - b.at);
  db.sendLogBackfilled = true;
  save();
}

/* ───────────────────────── 6. Webhook ───────────────────────── */

// Mengembalikan null bila valid, atau alasan penolakan (untuk log diagnosis)
function verifySignature(req) {
  const secret = meta().appSecret;
  if (!secret) return process.env.ALLOW_UNSIGNED_WEBHOOK === 'true' ? null : 'App Secret belum diisi (isi di Pengaturan atau set ALLOW_UNSIGNED_WEBHOOK=true untuk uji lokal)';
  const sig = req.get('x-hub-signature-256') || '';
  if (!sig) return 'header X-Hub-Signature-256 tidak ada (request bukan dari Meta, mis. curl/Postman)';
  if (!req.rawBody) return 'body mentah kosong (Content-Type bukan application/json?)';
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex');
  const ok = sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  return ok ? null : 'HMAC tidak cocok — App Secret salah/beda app, atau body diubah oleh proxy';
}

function parseInbound(m) {
  const t = m.type;
  if (['image', 'video', 'audio', 'document', 'sticker'].includes(t)) {
    const o = m[t] || {};
    return { type: t, content: { mediaId: o.id, mime: o.mime_type, caption: o.caption || '', filename: o.filename || '', voice: !!o.voice, ...(t === 'sticker' ? { animated: !!o.animated } : {}) } };
  }
  switch (t) {
    case 'text': return { type: 'text', content: { body: m.text?.body || '' } };
    case 'location': return { type: 'location', content: m.location || {} };
    case 'interactive': {
      if (m.interactive?.type === 'call_permission_reply') {
        const p = m.interactive.call_permission_reply || {};
        return { type: 'call_permission', content: { response: p.response === 'accept' ? 'accept' : 'reject', permanent: !!p.is_permanent, expiresAt: p.expiration_timestamp ? Number(p.expiration_timestamp) * 1000 : 0, source: p.response_source || '' } };
      }
      if (m.interactive?.type === 'nfm_reply') {
        // Jawaban WhatsApp Flow: response_json berisi flow_token + isian formulir
        const r = m.interactive.nfm_reply || {};
        let data = {};
        try { data = JSON.parse(r.response_json || '{}'); } catch { data = {}; }
        const { flow_token: token, ...response } = data && typeof data === 'object' ? data : {};
        return { type: 'flow_reply', content: { name: r.name || 'flow', body: r.body || 'Sent', token: String(token || ''), response } };
      }
      const r = m.interactive?.button_reply || m.interactive?.list_reply || {};
      return { type: 'interactive_reply', content: { id: r.id || '', title: r.title || r.name || 'Balasan', description: r.description || '' } };
    }
    case 'button': return { type: 'button', content: { text: m.button?.text || '', payload: m.button?.payload || '' } };
    case 'contacts': return { type: 'contacts', content: { contacts: (m.contacts || []).map((c) => ({ name: c.name?.formatted_name || [c.name?.first_name, c.name?.last_name].filter(Boolean).join(' ') || 'Kontak',
      phones: (c.phones || []).map((p) => p.phone), waIds: (c.phones || []).map((p) => p.wa_id || ''), emails: (c.emails || []).map((e) => e.email), company: c.org?.company || '' })) } };
    default: return { type: 'unsupported', content: { body: `[Pesan tipe "${t}" tidak didukung]` } };
  }
}

function handleMessages(value) {
  const profiles = Object.fromEntries((value.contacts || []).map((c) => [c.wa_id, c.profile?.name]));
  for (const m of value.messages || []) {
    if (idx.wamid.has(m.id)) continue; // dedup retry Meta
    if (m.group_id) { handleGroupMessage(m, profiles); continue; } // pesan grup: bukan percakapan pribadi pengirimnya
    const phone = normPhone(m.from);
    const contact = getOrCreateContact(phone, profiles[m.from]);
    const conv = getOrCreateConv(contact);
    if (m.type === 'reaction') {
      const target = idx.wamid.get(m.reaction?.message_id);
      if (target) {
        target.reaction = m.reaction.emoji || null; save();
        emitConv(conv, 'message:update', { message: target });
      }
      continue;
    }
    const { type, content } = parseInbound(m);
    if (type === 'call_permission') {
      contact.callPermission = { status: content.response, permanent: content.permanent, expiresAt: content.expiresAt, at: Number(m.timestamp) * 1000 || now() };
      contact.updatedAt = now();
    }
    const prevInboundAt = conv.lastInboundAt || 0, prevStatus = conv.status, prevUnread = conv.unread || 0;
    const msg = addMessage(conv, { direction: 'in', type, content, wamid: m.id, timestamp: Number(m.timestamp) * 1000 || now(), contextId: m.context?.id || null });
    if (type === 'flow_reply') recordFlowSubmission(conv, contact, msg);
    // Jawaban survei CSAT: jangan buka ulang percakapan yang sudah selesai, jangan beri notifikasi, jangan jalankan flow
    if (handleCsatReply(conv, contact, msg)) {
      Object.assign(conv, { status: prevStatus, unread: prevStatus === 'closed' ? prevUnread : conv.unread });
      save(); emitConv(conv, 'conversation:update', serializeConv(conv));
      continue;
    }
    if (type !== 'call_permission') notifyInboundMessage(conv, msg);
    // Flow otomatis lebih dulu; auto reply hanya bila tidak ada flow yang menjalankan aksi (mencegah balasan ganda)
    if (type !== 'call_permission') {
      runFlows(conv, contact, msg, prevInboundAt)
        .catch((e) => { console.warn('[flow]', e.message); return false; })
        .then((handled) => { if (!handled) runAutoReply(conv, contact, msg, prevInboundAt); });
    }
  }
}

/* ── Auto reply ──
 * Dijalankan di server untuk setiap pesan masuk. Urutan: kata kunci → di luar jam kerja → sambutan.
 * Balasan dikirim sebagai pesan teks biasa; aman terhadap aturan 24 jam karena pelanggan baru saja mengirim pesan.
 */
const DAYS = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'];
function autoReplyDefaults() {
  return {
    enabled: false, pauseMinutes: 30, keywordCooldownMin: 5,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'Asia/Jakarta',
    welcome: { enabled: false, text: 'Halo {{name}}, terima kasih telah menghubungi kami. Tim kami akan segera membalas pesan Anda.', inactiveDays: 30 },
    away: { enabled: false, text: 'Halo {{name}}, saat ini kami sedang di luar jam operasional. Pesan Anda akan kami balas pada jam kerja berikutnya.', cooldownHours: 12,
      hours: DAYS.map((_, day) => ({ day, enabled: day >= 1 && day <= 5, open: '08:00', close: '17:00' })) },
    rules: [], sent: 0, lastError: null,
  };
}
const arCfg = () => (db.autoReply = db.autoReply || autoReplyDefaults());
function zonedNow(tz, at = now()) {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: tz, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(at)).map((x) => [x.type, x.value]));
  return { day: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(p.weekday), time: `${p.hour}:${p.minute}` };
}
function isOpenNow(cfg, at) {
  const { day, time } = zonedNow(cfg.timezone, at);
  const h = cfg.away.hours.find((x) => x.day === day);
  if (!h?.enabled) return false;
  return h.close > h.open ? time >= h.open && time < h.close : time >= h.open || time < h.close; // dukung jam lewat tengah malam
}
const escRe = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function ruleMatches(rule, text) {
  const t = text.toLowerCase().trim();
  if (!t) return false;
  return rule.keywords.some((k) => {
    const kw = k.toLowerCase();
    if (rule.match === 'exact') return t === kw;
    if (rule.match === 'starts') return t.startsWith(kw);
    return new RegExp(`(^|[^\\p{L}\\p{N}])${escRe(kw)}($|[^\\p{L}\\p{N}])`, 'u').test(t); // kata utuh, bukan potongan kata
  });
}
const inboundText = (m) => (m.type === 'text' ? m.content.body : m.type === 'button' ? m.content.text : m.type === 'interactive_reply' ? m.content.title : '') || '';
// Tentukan balasan tanpa mengirim (dipakai juga oleh endpoint uji)
function decideAutoReply(cfg, { text, log = {}, prevInboundAt = 0, lastHumanReplyAt = 0, at = now() }) {
  if (!cfg.enabled) return { skip: 'Auto reply nonaktif.' };
  if (lastHumanReplyAt && at - lastHumanReplyAt < cfg.pauseMinutes * 60000) return { skip: `CS membalas dalam ${cfg.pauseMinutes} menit terakhir, auto reply dijeda.` };
  for (const rule of cfg.rules) {
    if (!rule.enabled || !ruleMatches(rule, text)) continue;
    if (at - (log[rule.id] || 0) < cfg.keywordCooldownMin * 60000) return { skip: `Aturan "${rule.name}" sudah membalas kontak ini dalam ${cfg.keywordCooldownMin} menit terakhir.` };
    return { key: rule.id, kind: 'keyword', label: rule.name, reply: rule.reply, rule, src: rule };
  }
  if (cfg.away.enabled && !isOpenNow(cfg, at)) {
    if (at - (log.away || 0) < cfg.away.cooldownHours * 3600000) return { skip: `Pesan di luar jam kerja sudah dikirim dalam ${cfg.away.cooldownHours} jam terakhir.` };
    return { key: 'away', kind: 'away', label: 'Di luar jam kerja', reply: cfg.away.text, src: cfg.away };
  }
  if (cfg.welcome.enabled && (!prevInboundAt || at - prevInboundAt > cfg.welcome.inactiveDays * 86400000)) {
    return { key: 'welcome', kind: 'welcome', label: 'Pesan sambutan', reply: cfg.welcome.text, src: cfg.welcome };
  }
  return { skip: 'Tidak ada aturan yang cocok.' };
}
const fillVars = (t, contact) => String(t).replace(/\{\{\s*(name|phone)\s*\}\}/g, (_, k) => (k === 'name' ? contact.name || contact.waName || 'Kak' : contact.phone));
async function runAutoReply(conv, contact, msg, prevInboundAt) {
  const cfg = arCfg();
  if (!cfg.enabled) return;
  const lastHuman = db.messages.filter((m) => m.conversationId === conv.id && m.direction === 'out' && m.userId).pop();
  conv.autoReplyLog = conv.autoReplyLog || {};
  const d = decideAutoReply(cfg, { text: inboundText(msg), log: conv.autoReplyLog, prevInboundAt, lastHumanReplyAt: lastHuman?.timestamp || 0 });
  if (!d.key) return;
  conv.autoReplyLog[d.key] = now(); // tandai sebelum mengirim agar pesan beruntun tidak memicu balasan ganda
  const src = d.src || {};
  try {
    await sendAutoContent(conv, contact, { text: d.reply, image: src.image, buttons: src.buttons },
      { auto: d.kind, userName: 'Auto reply', source: 'auto_reply', btnPrefix: `ar_${d.key}`, contextId: msg.wamid });
    cfg.sent = (cfg.sent || 0) + 1;
    if (d.rule) { d.rule.hits = (d.rule.hits || 0) + 1; d.rule.lastHitAt = now(); }
    save();
  } catch (e) {
    delete conv.autoReplyLog[d.key];
    cfg.lastError = { at: now(), message: e.message }; save();
    console.warn('[auto-reply]', e.message);
  }
}
/**
 * Kirim balasan otomatis (teks / gambar / tombol balasan) — dipakai auto reply dan flow otomatis.
 * src: { text, image (kunci db.arMedia), buttons[] }. o: { auto, userName, source, btnPrefix, contextId, flowId }
 */
async function sendAutoContent(conv, contact, src, o) {
  const buttons = (src.buttons || []).filter(Boolean);
  const body = fillVars(src.text || '', contact).slice(0, src.image || buttons.length ? 1024 : 4096);
  try {
    let payload, record;
    const mediaId = src.image ? await arMediaId(src.image) : null;
    if (buttons.length) {
      const interactive = { type: 'button', body: { text: body }, action: { buttons: buttons.map((title, i) => ({ type: 'reply', reply: { id: `${o.btnPrefix}_${i + 1}`, title } })) } };
      if (mediaId) interactive.header = { type: 'image', image: { id: mediaId } };
      payload = { type: 'interactive', interactive };
      record = { type: 'interactive', content: { kind: 'button', header: '', body, footer: '', buttons, arImage: src.image || null } };
    } else if (mediaId) {
      payload = { type: 'image', image: body ? { id: mediaId, caption: body } : { id: mediaId } };
      record = { type: 'image', content: { mediaId, caption: body, mime: db.arMedia[src.image]?.mime || 'image/jpeg', arImage: src.image } };
    } else {
      payload = { type: 'text', text: { body, preview_url: /https?:\/\//.test(body) } };
      record = { type: 'text', content: { body } };
    }
    const r = await sendToMeta({ messaging_product: 'whatsapp', recipient_type: 'individual', to: contact.phone, ...payload, ...(o.contextId ? { context: { message_id: o.contextId } } : {}) },
      { source: o.source, contact, conversation: conv, userName: o.userName });
    return addMessage(conv, { direction: 'out', ...record, wamid: r.messages?.[0]?.id, status: 'accepted', userName: o.userName, auto: o.auto, contextId: o.contextId || null, ...(o.flowId ? { flowId: o.flowId } : {}) });
  } catch (e) {
    if (src.image && db.arMedia[src.image]) db.arMedia[src.image].metaId = null; // unggah ulang pada percobaan berikutnya
    throw e;
  }
}
async function arMediaId(key) {
  const m = db.arMedia[key];
  if (!m) throw new HttpError(400, 'Gambar auto reply tidak ditemukan.');
  if (!m.metaId || now() - (m.metaAt || 0) > 25 * 86400000) {
    m.metaId = await uploadMedia({ buffer: Buffer.from(m.data, 'base64'), mimetype: m.mime, originalname: key + (m.mime === 'image/png' ? '.png' : '.jpg') });
    m.metaAt = now(); save();
  }
  return m.metaId;
}
function cleanReplyExtras(src, name, textRequired) {
  const text = str(src?.text ?? src?.reply, 4096);
  const image = src?.image && db.arMedia[src.image] ? src.image : null;
  const buttons = (Array.isArray(src?.buttons) ? src.buttons : []).map((t) => str(t, 20)).filter(Boolean).slice(0, 3);
  if (new Set(buttons.map((t) => t.toLowerCase())).size !== buttons.length) throw new HttpError(400, `${name}: teks tombol harus berbeda satu sama lain.`);
  if (textRequired) {
    if (!text && !(image && !buttons.length)) throw new HttpError(400, `${name}: isi teks balasan wajib diisi${buttons.length ? ' (wajib bila memakai tombol)' : ''}.`);
    if ((image || buttons.length) && text.length > 1024) throw new HttpError(400, `${name}: teks maksimal 1024 karakter bila memakai gambar atau tombol (sekarang ${text.length}).`);
  }
  return { text, image, buttons };
}
function validateAutoReply(b) {
  const cfg = arCfg(), out = structuredClone(cfg);
  const time = (v) => { if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(v)) throw new HttpError(400, `Jam tidak valid: "${v}" (format HH:MM).`); return v; };
  const num = (v, min, max, name) => { const n = Number(v); if (!Number.isFinite(n) || n < min || n > max) throw new HttpError(400, `${name} harus antara ${min}–${max}.`); return n; };
  out.enabled = !!b.enabled;
  out.pauseMinutes = num(b.pauseMinutes ?? 30, 0, 1440, 'Jeda saat CS aktif (menit)');
  out.keywordCooldownMin = num(b.keywordCooldownMin ?? 5, 0, 1440, 'Jeda balasan kata kunci (menit)');
  const tz = str(b.timezone, 64) || cfg.timezone;
  try { new Intl.DateTimeFormat('en-US', { timeZone: tz }); } catch { throw new HttpError(400, `Zona waktu tidak dikenal: ${tz}`); }
  out.timezone = tz;
  out.welcome = { enabled: !!b.welcome?.enabled, ...cleanReplyExtras(b.welcome, 'Pesan sambutan', !!b.welcome?.enabled), inactiveDays: num(b.welcome?.inactiveDays ?? 30, 1, 365, 'Hari tidak aktif') };
  const hours = Array.isArray(b.away?.hours) ? b.away.hours : cfg.away.hours;
  out.away = { enabled: !!b.away?.enabled, ...cleanReplyExtras(b.away, 'Pesan di luar jam kerja', !!b.away?.enabled), cooldownHours: num(b.away?.cooldownHours ?? 12, 0, 168, 'Jeda pesan di luar jam kerja (jam)'),
    hours: DAYS.map((_, day) => { const h = hours.find((x) => Number(x.day) === day) || {}; return { day, enabled: !!h.enabled, open: time(h.open || '08:00'), close: time(h.close || '17:00') }; }) };
  if (out.away.hours.some((h) => h.enabled && h.open === h.close)) throw new HttpError(400, 'Jam buka dan tutup tidak boleh sama.');
  const prev = Object.fromEntries(cfg.rules.map((x) => [x.id, x]));
  out.rules = (Array.isArray(b.rules) ? b.rules : []).slice(0, 100).map((x, i) => {
    const keywords = [...new Set(String(Array.isArray(x.keywords) ? x.keywords.join(',') : x.keywords || '').split(',').map((k) => k.trim().slice(0, 100)).filter(Boolean))].slice(0, 30);
    const name = str(x.name, 80) || `Aturan ${i + 1}`;
    if (!keywords.length) throw new HttpError(400, `"${name}": isi minimal satu kata kunci.`);
    const { text: reply, image, buttons } = cleanReplyExtras(x, `"${name}"`, true);
    const old = prev[x.id];
    return { id: old ? old.id : uid('r_'), name, match: ['exact', 'starts'].includes(x.match) ? x.match : 'contains', keywords, reply, image, buttons, enabled: x.enabled !== false, hits: old?.hits || 0, lastHitAt: old?.lastHitAt || 0 };
  });
  return out;
}

/* ── Flow otomatis (Automation Flow Builder) ──
 * Alur tanpa coding berbentuk pohon: Pemicu (pesan masuk) → Kondisi (cabang Ya/Tidak) → Aksi → ...
 * Setiap langkah hanya punya satu langkah sebelumnya, sehingga flow tidak mungkin berputar (loop).
 * Urutan: flow aktif dicek sesuai urutan; flow pertama yang menjalankan aksi menghentikan pengecekan, dan auto reply
 * lama tidak dijalankan untuk pesan tersebut.
 * Langkah "Tunggu" disimpan di db.flowRuns lalu dilanjutkan worker. Pesan bebas hanya dikirim selama jendela 24 jam
 * masih terbuka (dicek ulang tepat sebelum mengirim), dengan batas FLOW_MAX_AUTO_PER_HOUR pesan otomatis per percakapan.
 */
const FLOW_MAX_NODES = 60;
// Flow interaktif (tanya-jawab, hasil API berlembar) mengirim beberapa pesan per percakapan; batas ini tetap mencegah loop
const FLOW_MAX_AUTO_PER_HOUR = 30;
const FLOW_RUNS_MAX = 3000;
const FLOW_STEP_LABEL = { trigger: 'Pemicu', condition: 'Kondisi', send: 'Kirim pesan', ask: 'Tanya pelanggan', waflow: 'Kirim WhatsApp Flow', api: 'API Request', assign: 'Teruskan ke agen', label: 'Label kontak', status: 'Ubah status', note: 'Catatan internal', delay: 'Tunggu' };
const FLOW_COND_LABEL = { keyword: 'Kata kunci', variable: 'Variabel', schedule: 'Jadwal', business_hours: 'Jam kerja', label: 'Label kontak', new_contact: 'Kontak baru', message_type: 'Jenis pesan', assigned: 'Sudah ditugaskan' };
const FLOW_MSG_TYPES = ['text', 'image', 'video', 'audio', 'document', 'sticker', 'location', 'reply', 'flow_reply', 'contacts'];
const STATUS_LABEL = { open: 'Terbuka', pending: 'Menunggu', closed: 'Selesai' };
// Langkah bercabang: port pertama menerima lanjutan lama saat langkah disisipkan
const FLOW_PORTS = { condition: ['yes', 'no'], ask: ['next', 'fail'], waflow: ['next', 'fail'], api: ['next', 'fail'] };
const flowPorts = (type) => FLOW_PORTS[type] || ['next'];
const FLOW_VAR_OPS = ['eq', 'neq', 'contains', 'gt', 'gte', 'lt', 'lte', 'empty', 'not_empty'];
// Nama yang disediakan sistem untuk template, tidak boleh dipakai sebagai nama variabel
const FLOW_RESERVED_VARS = ['name', 'phone', 'today', 'pesan', 'item', 'no', 'page', 'pages', 'count', 'rest', 'secret'];
const FLOW_ACTIVE_RUN = ['waiting', 'input'];

const inTimeRange = (time, open, close) => (close > open ? time >= open && time < close : time >= open || time < close);
const zonedDate = (tz, at = now()) => new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(at));
const flowTz = () => arCfg().timezone;

/* Variabel & template flow: {{nama.path|filter:arg}}. Nilai HTML (mis. "<br />" dari API) diubah menjadi teks biasa. */
function getPath(obj, path) {
  let v = obj;
  for (const k of String(path).split('.')) {
    if (v == null) return undefined;
    if (k === 'length' && (Array.isArray(v) || typeof v === 'string')) { v = v.length; continue; }
    if (typeof v !== 'object' || !Object.prototype.hasOwnProperty.call(v, k)) return undefined; // aman dari __proto__
    v = v[k];
  }
  return v;
}
const htmlToText = (s) => String(s).replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, '')
  .replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&amp;/g, '&');
const ID_DAYS = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'];
const ID_MONTHS = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'];
const ymdDate = (ymd) => { const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(ymd || ''); return m ? new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])) : null; };
const ymdOf = (d) => d.toISOString().slice(0, 10);
const addDays = (ymd, n) => ymdOf(new Date(ymdDate(ymd).getTime() + n * 86400000));
const longDate = (ymd) => { const d = ymdDate(ymd); return d ? `${ID_DAYS[d.getUTCDay()]}, ${d.getUTCDate()} ${ID_MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}` : ymd; };
const shortDate = (ymd) => { const d = ymdDate(ymd); return `${ID_DAYS[d.getUTCDay()].slice(0, 3)}, ${d.getUTCDate()} ${ID_MONTHS[d.getUTCMonth()].slice(0, 3)}`; };
const TPL_FILTERS = {
  tanggal: (v) => (ymdDate(v) ? longDate(v) : v),
  jam: (v) => v.replace(/^(\d{1,2}[:.]\d{2})[:.]\d{2}/, '$1'),
  rupiah: (v) => (v !== '' && Number.isFinite(Number(v)) ? 'Rp' + Number(v).toLocaleString('id-ID') : v),
  angka: (v) => (v !== '' && Number.isFinite(Number(v)) ? Number(v).toLocaleString('id-ID') : v),
  upper: (v) => v.toUpperCase(), lower: (v) => v.toLowerCase(),
  default: (v, arg) => (v.trim() === '' ? arg : v),
};
// encode: 'url' (nilai di URL), 'json' (nilai di dalam string JSON), atau kosong (teks pesan)
function renderTpl(tpl, scope, encode) {
  return String(tpl ?? '').replace(/\{\{\s*([^{}]+?)\s*\}\}/g, (_, expr) => {
    const [path, ...filters] = expr.split('|').map((x) => x.trim());
    let v = getPath(scope, path);
    v = v == null || typeof v === 'object' ? '' : htmlToText(v).trim(); // objek/daftar tidak dicetak mentah
    for (const f of filters) { const [fn, ...arg] = f.split(':'); if (TPL_FILTERS[fn]) v = String(TPL_FILTERS[fn](v, arg.join(':'))); }
    return encode === 'url' ? encodeURIComponent(v) : encode === 'json' ? JSON.stringify(v).slice(1, -1) : v;
  });
}
const flowScope = (ctx, extra) => ({
  ...ctx.vars, name: ctx.contact.name || ctx.contact.waName || 'Kak', phone: ctx.contact.phone,
  today: zonedDate(flowTz(), ctx.at), pesan: ctx.text, ...extra,
});

/* HTTP keluar untuk langkah API Request: hanya HTTPS, tanpa redirect, dan tidak boleh ke alamat jaringan lokal/privat (SSRF) */
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const x = ip.toLowerCase();
  if (x.startsWith('::ffff:')) return isPrivateIp(x.slice(7));
  return x === '::1' || x === '::' || /^f[cd]/.test(x) || /^fe[89ab]/.test(x);
}
function safeLookup(host, opts, cb) {
  if (typeof opts === 'function') { cb = opts; opts = {}; }
  dns.lookup(host, { ...opts, all: true }, (err, addrs) => {
    if (err) return cb(err);
    // Tolak bila ADA alamat privat (mencegah DNS rebinding dengan campuran alamat publik & privat)
    if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) return cb(Object.assign(new Error('Alamat tujuan tidak diizinkan (jaringan lokal/privat).'), { code: 'EBLOCKED' }));
    return opts.all ? cb(null, addrs) : cb(null, addrs[0].address, addrs[0].family);
  });
}
const FLOW_HTTPS_AGENT = new https.Agent({ lookup: safeLookup, keepAlive: false });
const FLOW_API_MAX_BYTES = 512 * 1024;
// Kredensial API (mis. API key) disimpan terenkripsi; dipakai di langkah API sebagai {{secret.NAMA}}, tidak pernah dikirim ke browser
const flowSecretNames = () => Object.keys(db.settings.flowSecrets || {}).sort();
const flowSecrets = (masked) => Object.fromEntries(flowSecretNames().map((k) => [k, masked ? '••••' : decrypt(db.settings.flowSecrets[k])]));

/* Input tanggal untuk langkah "Tanya pelanggan": hasil selalu YYYY-MM-DD */
const MONTH_ALIAS = { jan: 1, feb: 2, peb: 2, mar: 3, apr: 4, mei: 5, may: 5, jun: 6, jul: 7, agu: 8, ags: 8, aug: 8, sep: 9, okt: 10, oct: 10, nov: 11, nop: 11, des: 12, dec: 12 };
function parseDateInput(text, today) {
  const t = String(text || '').trim().toLowerCase().replace(/\s+/g, ' ');
  const rel = { 'hari ini': 0, besok: 1, lusa: 2, kemarin: -1 }[t];
  if (rel !== undefined) return addDays(today, rel);
  let y, m, d, x;
  if ((x = /^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$/.exec(t))) [, y, m, d] = x;
  else if ((x = /^(\d{1,2})[-/. ](\d{1,2})[-/. ](\d{4})$/.exec(t))) [, d, m, y] = x;
  else if ((x = /^(\d{1,2})[-/.](\d{1,2})$/.exec(t))) { [, d, m] = x; y = today.slice(0, 4); }
  else if ((x = /^(\d{1,2}) ([a-z]+)\.?(?: (\d{4}))?$/.exec(t)) && MONTH_ALIAS[x[2].slice(0, 3)]) { d = x[1]; m = MONTH_ALIAS[x[2].slice(0, 3)]; y = x[3] || today.slice(0, 4); }
  else return null;
  const date = new Date(Date.UTC(+y, +m - 1, +d));
  if (date.getUTCFullYear() !== +y || date.getUTCMonth() !== +m - 1 || date.getUTCDate() !== +d) return null; // mis. 31-02-2026
  const ymd = ymdOf(date);
  return Math.abs(ymdDate(ymd) - ymdDate(today)) <= 400 * 86400000 ? ymd : null; // tahun salah ketik
}

function cleanFlowNode(raw, isRoot) {
  const type = String(raw?.type || '');
  if (!FLOW_STEP_LABEL[type]) throw new HttpError(400, `Jenis langkah tidak dikenal: "${type}".`);
  if (isRoot !== (type === 'trigger')) throw new HttpError(400, 'Pemicu hanya boleh ada satu, di awal flow.');
  const c = raw.cfg || {}, name = `Langkah "${FLOW_STEP_LABEL[type]}"`;
  const time = (v) => { if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(v || '')) throw new HttpError(400, `${name}: jam tidak valid (format HH:MM).`); return v; };
  const num = (v, min, max, label) => { const n = Number(v); if (!Number.isInteger(n) || n < min || n > max) throw new HttpError(400, `${name}: ${label} harus bilangan bulat ${min}–${max}.`); return n; };
  const varName = (v, label) => {
    const s = String(v || '').trim();
    if (!/^[a-z_][a-z0-9_]{0,39}$/i.test(s)) throw new HttpError(400, `${name}: ${label} hanya huruf, angka, garis bawah (mis. kata_kunci).`);
    if (FLOW_RESERVED_VARS.includes(s.toLowerCase())) throw new HttpError(400, `${name}: "${s}" dipakai sistem, pilih nama lain.`);
    return s;
  };
  const varPath = (v, label) => { const s = String(v || '').trim(); if (!/^[a-z_][a-z0-9_]*(\.[a-z0-9_]+){0,8}$/i.test(s)) throw new HttpError(400, `${name}: ${label} tidak valid (mis. hasil.data.length).`); return s; };
  const text = (v, max, label, fallback) => { const t = str(v, max) || fallback || ''; if (!t) throw new HttpError(400, `${name}: ${label} wajib diisi.`); return t; };
  let cfg = {};
  switch (type) {
    case 'trigger': break;
    case 'condition': {
      const kind = String(c.kind || '');
      if (!FLOW_COND_LABEL[kind]) throw new HttpError(400, `${name}: pilih jenis kondisi.`);
      cfg = { kind };
      if (kind === 'keyword') {
        cfg.match = ['exact', 'starts'].includes(c.match) ? c.match : 'contains';
        cfg.keywords = [...new Set((Array.isArray(c.keywords) ? c.keywords : String(c.keywords || '').split(',')).map((k) => String(k).trim().slice(0, 100)).filter(Boolean))].slice(0, 30);
        if (!cfg.keywords.length) throw new HttpError(400, `${name}: isi minimal satu kata kunci.`);
      } else if (kind === 'schedule') {
        cfg.days = [...new Set((Array.isArray(c.days) ? c.days : []).map(Number).filter((d) => Number.isInteger(d) && d >= 0 && d <= 6))].sort();
        if (!cfg.days.length) throw new HttpError(400, `${name}: pilih minimal satu hari.`);
        cfg.start = time(c.start); cfg.end = time(c.end);
        if (cfg.start === cfg.end) throw new HttpError(400, `${name}: jam mulai dan selesai tidak boleh sama.`);
      } else if (kind === 'label') {
        cfg.label = cleanLabels([c.label])[0] || '';
        if (!cfg.label) throw new HttpError(400, `${name}: isi nama label.`);
      } else if (kind === 'new_contact') {
        cfg.days = num(c.days ?? 30, 1, 365, 'hari tidak aktif');
      } else if (kind === 'message_type') {
        cfg.types = [...new Set((Array.isArray(c.types) ? c.types : []).filter((t) => FLOW_MSG_TYPES.includes(t)))];
        if (!cfg.types.length) throw new HttpError(400, `${name}: pilih minimal satu jenis pesan.`);
      } else if (kind === 'variable') {
        cfg.path = varPath(c.path, 'variabel');
        cfg.op = FLOW_VAR_OPS.includes(c.op) ? c.op : 'eq';
        cfg.value = ['empty', 'not_empty'].includes(cfg.op) ? '' : str(String(c.value ?? ''), 200);
      }
      break;
    }
    case 'send': {
      cfg = cleanReplyExtras(c, name, true);
      // Ulangi daftar dari variabel (mis. hasil API): teks pesan menjadi judul tiap lembar, item dirender per elemen
      if (c.repeat?.path) {
        const r = c.repeat;
        cfg.repeat = { path: varPath(r.path, 'daftar'), item: text(r.item, 1500, 'Format tiap item'), perMessage: num(r.perMessage ?? 5, 1, 20, 'item per pesan'),
          max: num(r.max ?? 30, 1, 100, 'jumlah item maksimal'), more: str(r.more, 500) };
        if (Math.ceil(cfg.repeat.max / cfg.repeat.perMessage) > 10) throw new HttpError(400, `${name}: maksimal 10 pesan per daftar (naikkan item per pesan atau turunkan jumlah maksimal).`);
        if (cfg.image || cfg.buttons.length) throw new HttpError(400, `${name}: daftar berulang hanya untuk pesan teks (tanpa gambar/tombol).`);
      }
      break;
    }
    case 'ask': {
      cfg = {
        text: text(c.text, 1024, 'Pertanyaan'), var: varName(c.var, 'Nama variabel'),
        input: ['text', 'choice', 'date'].includes(c.input) ? c.input : 'text',
        invalidText: text(c.invalidText, 1024, 'Pesan bila jawaban tidak valid', 'Jawaban belum sesuai. Silakan coba lagi, atau ketik *batal*.'),
        retries: num(c.retries ?? 2, 0, 3, 'kesempatan ulang'), timeoutMinutes: num(c.timeoutMinutes ?? 30, 1, 1380, 'batas waktu (menit)'),
      };
      if (cfg.input === 'text') {
        cfg.minLength = num(c.minLength ?? 1, 1, 200, 'panjang minimal');
        cfg.maxLength = num(c.maxLength ?? 100, cfg.minLength, 500, 'panjang maksimal');
        cfg.format = ['any', 'search', 'digits', 'alnum'].includes(c.format) ? c.format : 'any';
      } else if (cfg.input === 'choice') {
        cfg.choices = (Array.isArray(c.choices) ? c.choices : []).map((x) => ({ title: str(x?.title, 24), value: str(String(x?.value ?? ''), 200) || str(x?.title, 24) })).filter((x) => x.title).slice(0, 10);
        if (!cfg.choices.length) throw new HttpError(400, `${name}: isi minimal satu pilihan.`);
        if (new Set(cfg.choices.map((x) => x.title.toLowerCase())).size !== cfg.choices.length) throw new HttpError(400, `${name}: judul pilihan harus berbeda.`);
        if (cfg.choices.length <= 3 && cfg.choices.some((x) => x.title.length > 20)) throw new HttpError(400, `${name}: judul tombol maks. 20 karakter (bila ≤ 3 pilihan).`);
        cfg.button = text(c.button, 20, 'Teks tombol daftar', 'Pilih');
      } else {
        cfg.days = num(c.days ?? 2, 1, 9, 'jumlah tanggal');
        cfg.skipWeekends = c.skipWeekends !== false; cfg.includeToday = c.includeToday !== false;
        cfg.otherLabel = text(c.otherLabel, 20, 'Teks tombol tanggal lain', 'Tanggal lain');
        cfg.otherPrompt = text(c.otherPrompt, 1024, 'Pesan meminta tanggal', 'Ketik tanggal dengan format DD-MM-YYYY, contoh: 21-10-2026.');
        cfg.button = text(c.button, 20, 'Teks tombol daftar', 'Pilih tanggal');
      }
      break;
    }
    case 'waflow': {
      const f = wafById(c.flowId);
      if (!f) throw new HttpError(400, `${name}: pilih WhatsApp Flow (sinkronkan di menu WhatsApp Flows).`);
      cfg = { flowId: f.id, text: text(c.text, 1024, 'Teks pesan'), cta: text(c.cta, 30, 'Teks tombol'), header: str(c.header, 60), footer: str(c.footer, 60),
        screen: str(c.screen, 80), var: varName(c.var, 'Simpan jawaban ke variabel'), timeoutMinutes: num(c.timeoutMinutes ?? 60, 1, 1380, 'batas waktu (menit)') };
      break;
    }
    case 'api': {
      cfg.method = c.method === 'POST' ? 'POST' : 'GET';
      cfg.url = text(c.url, 1000, 'URL');
      // Host harus statis: variabel hanya boleh di path/query, agar tujuan tidak bisa dibelokkan oleh input pelanggan
      const m = /^https:\/\/([^/?#]+)/i.exec(cfg.url);
      if (!m) throw new HttpError(400, `${name}: URL harus diawali https://`);
      if (/[{}]/.test(m[1])) throw new HttpError(400, `${name}: nama host tidak boleh berisi variabel.`);
      try { new URL(renderTpl(cfg.url, {}, 'url')); } catch { throw new HttpError(400, `${name}: URL tidak valid.`); }
      cfg.headers = (Array.isArray(c.headers) ? c.headers : []).slice(0, 10).map((h) => ({ name: str(h?.name, 60), value: str(h?.value, 1000) })).filter((h) => h.name);
      for (const h of cfg.headers) {
        if (!/^[A-Za-z0-9-]+$/.test(h.name) || ['host', 'content-length', 'connection', 'transfer-encoding'].includes(h.name.toLowerCase())) throw new HttpError(400, `${name}: header "${h.name}" tidak diizinkan.`);
        for (const [, s] of h.value.matchAll(/\{\{\s*secret\.([A-Z0-9_]+)\s*\}\}/g)) if (!db.settings.flowSecrets?.[s]) throw new HttpError(400, `${name}: kredensial "${s}" belum dibuat.`);
      }
      cfg.body = cfg.method === 'POST' ? str(c.body, 4000) : '';
      if (cfg.body) { try { JSON.parse(renderTpl(cfg.body, {}, 'json')); } catch { throw new HttpError(400, `${name}: body harus JSON valid.`); } }
      cfg.timeoutSec = num(c.timeoutSec ?? 10, 1, 20, 'timeout (detik)');
      cfg.saveAs = varName(c.saveAs, 'Simpan respons sebagai');
      cfg.okPath = c.okPath ? varPath(c.okPath, 'field penanda berhasil') : '';
      cfg.okValue = cfg.okPath ? str(String(c.okValue ?? ''), 100) : '';
      break;
    }
    case 'assign': {
      cfg.mode = ['user', 'round_robin', 'least_busy'].includes(c.mode) ? c.mode : 'least_busy';
      cfg.onlyIfUnassigned = c.onlyIfUnassigned !== false;
      if (cfg.mode === 'user') {
        const u = byId('users', String(c.userId || ''));
        if (!u || !u.active) throw new HttpError(400, `${name}: pilih agen yang aktif.`);
        cfg.userId = u.id;
      }
      break;
    }
    case 'label':
      cfg = { label: cleanLabels([c.label])[0] || '', remove: !!c.remove };
      if (!cfg.label) throw new HttpError(400, `${name}: isi nama label.`);
      break;
    case 'status':
      if (!STATUS_LABEL[c.status]) throw new HttpError(400, `${name}: status tidak valid.`);
      cfg = { status: c.status };
      break;
    case 'note':
      cfg = { text: str(c.text, 2000) };
      if (!cfg.text) throw new HttpError(400, `${name}: isi catatan.`);
      break;
    case 'delay':
      // Maks. 23 jam: lewat dari itu jendela layanan 24 jam hampir pasti sudah tertutup
      cfg = { minutes: num(c.minutes, 1, 1380, 'durasi (menit)'), cancelOnReply: c.cancelOnReply !== false };
      break;
  }
  return { id: raw.id, type, cfg };
}

function validateFlow(b, prev) {
  const name = str(b.name, 80);
  if (!name) throw new HttpError(400, 'Nama flow wajib diisi.');
  const src = b.nodes && typeof b.nodes === 'object' && !Array.isArray(b.nodes) ? b.nodes : {};
  if (Object.keys(src).length > FLOW_MAX_NODES) throw new HttpError(400, `Flow maksimal ${FLOW_MAX_NODES} langkah.`);
  const root = String(b.root || '');
  if (!src[root]) throw new HttpError(400, 'Flow harus diawali pemicu.');
  const nodes = {}, seen = new Set();
  // Telusuri dari pemicu; langkah yang tidak terhubung dibuang
  const visit = (id) => {
    if (id == null || id === '') return null;
    id = String(id);
    if (!/^[\w-]{1,40}$/.test(id) || !src[id]) throw new HttpError(400, 'Flow merujuk langkah yang tidak ada.');
    if (seen.has(id)) throw new HttpError(400, 'Setiap langkah hanya boleh memiliki satu langkah sebelumnya.');
    seen.add(id);
    const n = cleanFlowNode({ ...src[id], id }, id === root);
    nodes[id] = n;
    for (const p of flowPorts(n.type)) n[p] = visit(src[id][p]);
    return id;
  };
  visit(root);
  const s = b.settings || {};
  const num = (v, min, max, label) => { const n = Number(v); if (!Number.isInteger(n) || n < min || n > max) throw new HttpError(400, `${label} harus bilangan bulat ${min}–${max}.`); return n; };
  const date = (v, label) => { const d = str(v, 10); if (d && !/^\d{4}-\d{2}-\d{2}$/.test(d)) throw new HttpError(400, `${label} tidak valid.`); return d; };
  const settings = {
    pauseIfHumanMin: num(s.pauseIfHumanMin ?? 30, 0, 1440, 'Jeda saat CS aktif'),
    cooldownMin: num(s.cooldownMin ?? 0, 0, 10080, 'Jeda menjalankan ulang'),
    activeFrom: date(s.activeFrom, 'Tanggal mulai'), activeUntil: date(s.activeUntil, 'Tanggal selesai'),
    // Saat flow menunggu jawaban (langkah Tanya pelanggan), pelanggan dapat membatalkan dengan kata ini
    cancelWords: [...new Set((Array.isArray(s.cancelWords) ? s.cancelWords : String(s.cancelWords ?? 'batal').split(',')).map((w) => String(w).trim().toLowerCase().slice(0, 30)).filter(Boolean))].slice(0, 10),
    cancelText: str(s.cancelText, 500) || 'Baik, permintaan dibatalkan.',
  };
  if (settings.activeFrom && settings.activeUntil && settings.activeFrom > settings.activeUntil) throw new HttpError(400, 'Tanggal mulai harus sebelum tanggal selesai.');
  if (Object.values(nodes).every((n) => n.type === 'trigger' || n.type === 'condition')) throw new HttpError(400, 'Tambahkan minimal satu aksi (mis. Kirim pesan atau Teruskan ke agen).');
  return {
    id: prev?.id || uid('f_'), name, enabled: b.enabled === undefined ? !!prev?.enabled : !!b.enabled, root, nodes, settings,
    order: prev?.order ?? Math.max(0, ...db.flows.map((f) => f.order || 0)) + 1, rr: prev?.rr || 0,
    stats: prev?.stats || { runs: 0, actions: 0, lastRunAt: 0, lastError: null }, createdAt: prev?.createdAt || now(), updatedAt: now(),
  };
}

function evalFlowCond(cfg, ctx) {
  switch (cfg.kind) {
    case 'keyword': return ruleMatches(cfg, ctx.text);
    case 'schedule': return cfg.days.includes(ctx.clock.day) && inTimeRange(ctx.clock.time, cfg.start, cfg.end);
    case 'business_hours': {
      const h = arCfg().away.hours.find((x) => x.day === ctx.clock.day);
      return !!h?.enabled && inTimeRange(ctx.clock.time, h.open, h.close);
    }
    case 'label': return (ctx.contact.labels || []).includes(cfg.label);
    case 'new_contact': return !ctx.prevInboundAt || ctx.at - ctx.prevInboundAt > cfg.days * 86400000;
    case 'message_type': return cfg.types.includes(['interactive_reply', 'button'].includes(ctx.msgType) ? 'reply' : ctx.msgType);
    case 'assigned': return !!ctx.conv.assignedTo;
    case 'variable': {
      const v = getPath(flowScope(ctx), cfg.path);
      const empty = v == null || v === '' || (Array.isArray(v) && !v.length) || (typeof v === 'object' && !Array.isArray(v) && !Object.keys(v).length);
      if (cfg.op === 'empty') return empty;
      if (cfg.op === 'not_empty') return !empty;
      const a = Array.isArray(v) ? v.length : v, s = a == null ? '' : String(a), w = cfg.value;
      const bothNum = s !== '' && w !== '' && Number.isFinite(Number(s)) && Number.isFinite(Number(w));
      switch (cfg.op) {
        case 'eq': return bothNum ? Number(s) === Number(w) : s.toLowerCase() === w.toLowerCase();
        case 'neq': return bothNum ? Number(s) !== Number(w) : s.toLowerCase() !== w.toLowerCase();
        case 'contains': return s.toLowerCase().includes(w.toLowerCase());
        case 'gt': return bothNum && Number(s) > Number(w);
        case 'gte': return bothNum && Number(s) >= Number(w);
        case 'lt': return bothNum && Number(s) < Number(w);
        case 'lte': return bothNum && Number(s) <= Number(w);
        default: return false;
      }
    }
    default: return false;
  }
}
function flowAgents() {
  const active = db.users.filter((u) => u.active);
  const agents = active.filter((u) => u.role === 'agent');
  return agents.length ? agents : active;
}
function pickAgent(flow, cfg) {
  if (cfg.mode === 'user') { const u = byId('users', cfg.userId); return u?.active ? u : null; }
  const list = flowAgents().sort((a, b) => a.id.localeCompare(b.id));
  if (!list.length) return null;
  if (cfg.mode === 'round_robin') return list[(flow.rr || 0) % list.length];
  const open = (u) => db.conversations.filter((c) => c.assignedTo === u.id && c.status !== 'closed').length;
  return list.map((u) => [u, open(u)]).sort((a, b) => a[1] - b[1])[0][0];
}
const recentAutoCount = (conv, since) => {
  let n = 0;
  for (let i = db.messages.length - 1; i >= 0; i--) {
    const m = db.messages[i];
    if (m.timestamp < since) break;
    if (m.conversationId === conv.id && m.direction === 'out' && m.auto) n++;
  }
  return n;
};

// Pesan dari daftar (mis. hasil API): dipecah per perMessage item & ≤ 3500 karakter. null = daftar kosong / bukan daftar.
function buildRepeat(c, scope) {
  const list = getPath(scope, c.repeat.path);
  if (!Array.isArray(list) || !list.length) return null;
  const shown = list.slice(0, c.repeat.max);
  const items = shown.map((item, i) => renderTpl(c.repeat.item, { ...scope, item, no: i + 1 }).slice(0, 3500));
  const chunks = []; let cur = [], len = 0;
  for (const t of items) {
    if (cur.length && (cur.length >= c.repeat.perMessage || len + t.length > 3500)) { chunks.push(cur); cur = []; len = 0; }
    cur.push(t); len += t.length + 2;
  }
  if (cur.length) chunks.push(cur);
  const kept = chunks.slice(0, 10), rest = list.length - kept.reduce((t, x) => t + x.length, 0);
  return kept.map((part, i) => {
    const sc = { ...scope, count: list.length, page: i + 1, pages: kept.length, rest };
    let text = [renderTpl(c.text, sc), part.join('\n\n')].filter(Boolean).join('\n\n');
    if (i === kept.length - 1 && rest > 0 && c.repeat.more) text += '\n\n' + renderTpl(c.repeat.more, sc);
    return { text: text.slice(0, 4096), image: null, buttons: [] };
  });
}
// Kirim satu pesan otomatis dari flow dengan pengaman (jendela 24 jam, batas per jam). Mengembalikan pesan error atau null.
async function flowDeliver(flow, n, ctx, payloadFn) {
  if (!windowOpen(ctx.conv)) return 'di luar jendela layanan 24 jam';
  if (recentAutoCount(ctx.conv, now() - 3600000) >= FLOW_MAX_AUTO_PER_HOUR) return `batas ${FLOW_MAX_AUTO_PER_HOUR} pesan otomatis per jam untuk percakapan ini tercapai`;
  try { await payloadFn(); ctx.contextId = null; return null; } // hanya pesan pertama yang mengutip pesan pelanggan
  catch (e) { return e.message; }
}
const flowSendText = (flow, n, ctx, m) => flowDeliver(flow, n, ctx, () => sendAutoContent(ctx.conv, ctx.contact, m,
  { auto: 'flow', userName: 'Flow: ' + flow.name, source: 'flow', btnPrefix: `fl_${n.id}`, contextId: ctx.contextId, flowId: flow.id }));

/* Langkah "Tanya pelanggan" */
function askOptions(c, ctx) {
  if (c.input === 'choice') return c.choices.map((x) => ({ title: x.title, value: x.value }));
  if (c.input !== 'date') return [];
  const today = zonedDate(flowTz(), ctx.at), out = [];
  for (let i = c.includeToday ? 0 : 1; out.length < c.days && i < 60; i++) {
    const ymd = addDays(today, i), wd = ymdDate(ymd).getUTCDay();
    if (c.skipWeekends && (wd === 0 || wd === 6)) continue;
    const d = ymdDate(ymd), dm = `${d.getUTCDate()} ${ID_MONTHS[d.getUTCMonth()].slice(0, 3)}`;
    out.push({ title: i === 0 ? `Hari ini, ${dm}` : i === 1 ? `Besok, ${dm}` : shortDate(ymd), value: ymd, desc: longDate(ymd) });
  }
  out.push({ title: c.otherLabel, other: true, desc: 'Ketik tanggal sendiri' });
  return out;
}
// Pertanyaan dengan pilihan: ≤ 3 → tombol balasan, selebihnya → pesan daftar. ID balasan: fq_<langkah>_<indeks>
function askInteractive(n, body, options) {
  const c = n.cfg;
  if (options.length <= 3) {
    return { type: 'interactive', interactive: { type: 'button', body: { text: body }, action: { buttons: options.map((o, i) => ({ type: 'reply', reply: { id: `fq_${n.id}_${i}`, title: o.title.slice(0, 20) } })) } },
      record: { type: 'interactive', content: { kind: 'button', header: '', body, footer: '', buttons: options.map((o) => o.title.slice(0, 20)) } } };
  }
  const rows = options.map((o, i) => ({ id: `fq_${n.id}_${i}`, title: o.title.slice(0, 24), ...(o.desc ? { description: o.desc.slice(0, 72) } : {}) }));
  return { type: 'interactive', interactive: { type: 'list', body: { text: body }, action: { button: c.button, sections: [{ title: 'Pilihan', rows }] } },
    record: { type: 'interactive', content: { kind: 'list', header: '', body, footer: '', button: c.button, rows: rows.map((r) => ({ id: r.id, title: r.title, description: r.description || '' })) } } };
}
async function askSend(flow, n, ctx, body, options, dry) {
  const preview = { text: body, buttons: options.map((o) => o.title) };
  if (dry) return { preview };
  if (!options.length) return { preview, error: await flowSendText(flow, n, ctx, { text: body, image: null, buttons: [] }) };
  const m = askInteractive(n, body, options);
  const error = await flowDeliver(flow, n, ctx, async () => {
    const r = await sendToMeta({ messaging_product: 'whatsapp', recipient_type: 'individual', to: ctx.contact.phone, type: m.type, interactive: m.interactive, ...(ctx.contextId ? { context: { message_id: ctx.contextId } } : {}) },
      { source: 'flow', contact: ctx.contact, conversation: ctx.conv, userName: 'Flow: ' + flow.name });
    addMessage(ctx.conv, { direction: 'out', ...m.record, wamid: r.messages?.[0]?.id, status: 'accepted', userName: 'Flow: ' + flow.name, auto: 'flow', flowId: flow.id, contextId: ctx.contextId || null });
  });
  return { preview, error };
}
const ASK_FORMATS = { search: /^[\p{L}\p{N}][\p{L}\p{N} .,'/-]*$/u, digits: /^\d+$/, alnum: /^[\p{L}\p{N} ]+$/u };
// Nilai jawaban: { value, label } | { other } | { cancel } | { invalid }
function evalAnswer(flow, c, st, msg, ctx) {
  const id = msg.type === 'interactive_reply' ? String(msg.content?.id || '') : '';
  const text = String(inboundText(msg) || '').replace(/[\u0000-\u001f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (flow.settings.cancelWords?.includes(text.toLowerCase())) return { cancel: true };
  const pick = (o) => (o ? (o.other ? { other: true } : { value: o.value, label: o.title }) : null);
  if (id.startsWith(`fq_${st.nodeId}_`)) { const o = pick(st.options[Number(id.slice(id.lastIndexOf('_') + 1))]); if (o) return o; }
  if (st.options.length && !st.typed) {
    // Pelanggan boleh mengetik nomor urut atau judul pilihan
    const o = pick(/^\d{1,2}$/.test(text) ? st.options[Number(text) - 1] : st.options.find((x) => x.title.toLowerCase() === text.toLowerCase()));
    if (o) return o;
  }
  if (c.input === 'date') { const ymd = parseDateInput(text, zonedDate(flowTz(), ctx.at)); return ymd ? { value: ymd, label: longDate(ymd) } : { invalid: true }; }
  if (c.input === 'choice') return { invalid: true };
  const len = [...text].length;
  if (msg.type !== 'text' && !id && !text) return { invalid: true };
  if (len < c.minLength || len > c.maxLength || (ASK_FORMATS[c.format] && !ASK_FORMATS[c.format].test(text))) return { invalid: true };
  return { value: text, label: text };
}
// Live: pertanyaan dikirim lalu run menunggu (status "input"); jawaban berikutnya masuk lewat ctx.answer.
// Simulasi: jawaban diambil dari ctx.dryAnswers secara berurutan.
async function execAsk(flow, n, ctx, dry) {
  const c = n.cfg, logs = [], previews = [];
  let st = ctx.answer?.state?.nodeId === n.id ? ctx.answer.state : null;
  const say = async (body, options) => {
    const r = await askSend(flow, n, ctx, renderTpl(body, flowScope(ctx)), options, dry);
    previews.push(r.preview);
    return r.error;
  };
  const wait = (log) => ({ waitInput: st, log: [...logs, log].join(' → '), action: true, previews });
  if (!st) {
    st = { nodeId: n.id, options: askOptions(c, ctx), tries: 0, typed: c.input === 'text', since: now(), expiresAt: now() + c.timeoutMinutes * 60000 };
    const err = await say(c.text, st.options);
    if (err) return { next: null, ok: false, log: 'Pertanyaan tidak terkirim: ' + err };
    logs.push('Pertanyaan dikirim');
    if (!dry) return wait('menunggu jawaban');
  }
  for (;;) {
    const msg = dry ? (ctx.dryAnswers.length ? { type: 'text', content: { body: ctx.dryAnswers.shift() } } : null) : ctx.answer?.msg;
    if (ctx.answer) ctx.answer = null; // jawaban hanya untuk langkah ini
    if (!msg) return { stop: true, action: true, log: [...logs, 'menunggu jawaban pelanggan (isi "Jawaban uji" untuk melanjutkan simulasi)'].join(' → '), previews };
    if (dry) logs.push(`Pelanggan: "${inboundText(msg)}"`);
    const a = evalAnswer(flow, c, st, msg, ctx);
    if (a.cancel) {
      if (!dry) await flowSendText(flow, n, ctx, { text: renderTpl(flow.settings.cancelText, flowScope(ctx)), image: null, buttons: [] });
      else previews.push({ text: flow.settings.cancelText });
      return { next: null, cancelled: true, log: [...logs, 'dibatalkan pelanggan'].join(' → '), previews };
    }
    if (a.other) {
      st.typed = true;
      const err = await say(c.otherPrompt, []);
      if (err) return { next: null, ok: false, log: [...logs, 'Gagal meminta tanggal: ' + err].join(' → '), previews };
      logs.push('Minta ketik tanggal');
      if (!dry) return wait('menunggu tanggal');
      continue;
    }
    if (!a.invalid) {
      ctx.vars[c.var] = a.value; ctx.vars[c.var + '_label'] = a.label;
      return { next: n.next, branch: 'next', log: [...logs, `${c.var} = ${a.value}`].join(' → '), previews };
    }
    st.tries++;
    if (st.tries > c.retries) {
      ctx.vars[c.var] = '';
      return { next: n.fail, branch: 'fail', log: [...logs, `Jawaban tidak valid ${st.tries}×, lanjut cabang Tidak valid`].join(' → '), previews };
    }
    // Ulangi pertanyaan dengan pilihan yang sama agar tombol tetap bisa ditekan
    const err = await say(c.invalidText, st.typed ? [] : st.options);
    if (err) return { next: null, ok: false, log: [...logs, 'Gagal mengirim ulang: ' + err].join(' → '), previews };
    logs.push(`Tidak valid (${st.tries}/${c.retries})`);
    if (!dry) return wait('menunggu jawaban ulang');
  }
}

/* Langkah "API Request" */
async function execApi(flow, n, ctx, dry) {
  const c = n.cfg, scope = flowScope(ctx);
  const real = (tpl, enc) => renderTpl(tpl, { ...scope, secret: flowSecrets(false) }, enc);
  const shownUrl = renderTpl(c.url, { ...scope, secret: flowSecrets(true) }, 'url'); // kredensial disamarkan di log
  const fail = (msg, extra = {}) => {
    ctx.vars[c.saveAs] = extra.json ?? null; ctx.vars[c.saveAs + '_status'] = extra.status || 0; ctx.vars[c.saveAs + '_error'] = msg;
    return { next: n.fail, branch: 'fail', ok: false, log: `${c.method} ${shownUrl} → ${msg}`, ...(extra.preview ? { preview: extra.preview } : {}) };
  };
  if (dry && (!ctx.liveApi || c.method !== 'GET')) {
    ctx.vars[c.saveAs] = null; ctx.vars[c.saveAs + '_status'] = 0; ctx.vars[c.saveAs + '_error'] = '';
    return { next: n.next, branch: 'next', log: `${c.method} ${shownUrl} → tidak dipanggil saat uji${c.method !== 'GET' ? ' (hanya GET yang dipanggil)' : ''}; lanjut cabang Berhasil tanpa data` };
  }
  const url = real(c.url, 'url');
  if (!/^https:\/\//i.test(url)) return fail('URL harus HTTPS');
  // Alamat IP literal tidak melewati DNS lookup, jadi diperiksa di sini
  let host;
  try { host = new URL(url).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch { return fail('URL tidak valid'); }
  if (host === 'localhost' || host.endsWith('.localhost') || (net.isIP(host) && isPrivateIp(host))) return fail('Alamat tujuan tidak diizinkan (jaringan lokal/privat).');
  const headers = { Accept: 'application/json', 'User-Agent': 'Kontaq-Flow/1.0' };
  for (const h of c.headers) headers[h.name] = real(h.value).replace(/[\r\n]/g, '');
  const body = c.method === 'POST' && c.body ? real(c.body, 'json') : undefined;
  if (body) headers['Content-Type'] = 'application/json';
  const started = Date.now();
  let res;
  try {
    res = await axios({ method: c.method, url, headers, data: body, timeout: c.timeoutSec * 1000, maxRedirects: 0, proxy: false,
      maxContentLength: FLOW_API_MAX_BYTES, maxBodyLength: 64 * 1024, responseType: 'text', transformResponse: [(d) => d],
      validateStatus: () => true, httpsAgent: FLOW_HTTPS_AGENT });
  } catch (e) {
    const msg = e.code === 'ECONNABORTED' || e.code === 'ETIMEDOUT' || /timeout/i.test(e.message) ? `waktu habis (${c.timeoutSec} dtk)`
      : e.code === 'EBLOCKED' ? e.message : /maxContentLength/i.test(e.message) ? 'respons terlalu besar' : 'gagal terhubung: ' + (e.code || e.message);
    return fail(msg);
  }
  const ms = ((Date.now() - started) / 1000).toFixed(1).replace('.', ',');
  let json = null;
  try { json = JSON.parse(res.data); } catch { /* bukan JSON */ }
  const preview = dry ? { json: String(res.data || '').slice(0, 800) } : null;
  if (json === null) return fail(`HTTP ${res.status} (${ms} dtk), respons bukan JSON`, { status: res.status, preview });
  if (res.status < 200 || res.status >= 300) return fail(`HTTP ${res.status} (${ms} dtk)`, { status: res.status, json, preview });
  if (c.okPath && String(getPath(json, c.okPath)) !== c.okValue) return fail(`HTTP ${res.status} (${ms} dtk), ${c.okPath} = ${JSON.stringify(getPath(json, c.okPath))}`, { status: res.status, json, preview });
  ctx.vars[c.saveAs] = json; ctx.vars[c.saveAs + '_status'] = res.status; ctx.vars[c.saveAs + '_error'] = '';
  return { next: n.next, branch: 'next', action: true, log: `${c.method} ${shownUrl} → HTTP ${res.status} (${ms} dtk)`, ...(preview ? { preview } : {}) };
}

/* Langkah "Kirim WhatsApp Flow": kirim formulir lalu tunggu jawaban (nfm_reply dengan flow_token yang sama).
 * Cabang Diisi: isian disimpan ke variabel. Cabang Tidak diisi: dijalankan worker bila batas waktu habis. */
async function execWaFlow(flow, n, ctx, dry) {
  const c = n.cfg, st = ctx.answer?.state?.nodeId === n.id ? ctx.answer.state : null;
  if (st) {
    const msg = ctx.answer.msg; ctx.answer = null;
    if (ctx.timedOut) return { next: n.fail, branch: 'fail', log: `Formulir tidak diisi dalam ${fmtMinutes(c.timeoutMinutes)}` };
    ctx.vars[c.var] = msg.content.response || {};
    return { next: n.next, branch: 'next', log: `Formulir diisi → ${c.var} (${Object.keys(msg.content.response || {}).join(', ') || 'kosong'})` };
  }
  const scope = flowScope(ctx);
  let m;
  try { m = buildWaFlowMessage({ flowId: c.flowId, body: renderTpl(c.text, scope), cta: c.cta, header: renderTpl(c.header, scope), footer: renderTpl(c.footer, scope), screen: c.screen }); }
  catch (e) { return { next: n.fail, branch: 'fail', ok: false, log: 'Formulir tidak dapat dikirim: ' + e.message }; }
  const preview = { text: m.content.body, buttons: ['📋 ' + m.content.button] };
  if (dry) {
    // Simulasi: jawaban uji berupa JSON objek, mis. {"nama":"Budi"}
    const raw = ctx.dryAnswers.shift();
    if (!raw) return { stop: true, action: true, log: `Formulir "${m.content.flowName}" dikirim → menunggu jawaban (isi "Jawaban uji" dengan JSON, mis. {"nama":"Budi"})`, previews: [preview] };
    let data;
    try { data = JSON.parse(raw); } catch { data = null; }
    if (!data || typeof data !== 'object' || Array.isArray(data)) return { next: n.fail, branch: 'fail', log: `Jawaban uji bukan objek JSON: ${raw}`, previews: [preview] };
    ctx.vars[c.var] = data;
    return { next: n.next, branch: 'next', action: true, log: `Formulir dikirim → diisi (${Object.keys(data).join(', ')})`, previews: [preview] };
  }
  const err = await flowDeliver(flow, n, ctx, async () => {
    const r = await sendToMeta({ messaging_product: 'whatsapp', recipient_type: 'individual', to: ctx.contact.phone, type: 'interactive', interactive: m.interactive },
      { source: 'flow', contact: ctx.contact, conversation: ctx.conv, userName: 'Flow: ' + flow.name });
    addMessage(ctx.conv, { direction: 'out', type: 'interactive', content: m.content, wamid: r.messages?.[0]?.id, status: 'accepted', userName: 'Flow: ' + flow.name, auto: 'flow', flowId: flow.id });
  });
  if (err) return { next: n.fail, branch: 'fail', ok: false, log: 'Formulir tidak terkirim: ' + err };
  return { waitInput: { kind: 'flow', nodeId: n.id, token: m.token, since: now(), expiresAt: now() + c.timeoutMinutes * 60000 }, action: true, log: `Formulir "${m.content.flowName}" dikirim → menunggu jawaban`, previews: [preview] };
}

// Satu langkah. dry = simulasi (tanpa efek samping). Mengembalikan { next, log, ok, action, wait, preview }
async function execFlowNode(flow, n, ctx, dry) {
  const c = n.cfg;
  switch (n.type) {
    case 'trigger': return { next: n.next, log: 'Pesan masuk dari pelanggan' };
    case 'condition': {
      const yes = evalFlowCond(c, ctx);
      return { next: yes ? n.yes : n.no, log: `${FLOW_COND_LABEL[c.kind]}${c.kind === 'variable' ? ` (${c.path})` : ''}: ${yes ? 'Ya' : 'Tidak'}`, branch: yes ? 'yes' : 'no' };
    }
    case 'ask': return execAsk(flow, n, ctx, dry);
    case 'waflow': return execWaFlow(flow, n, ctx, dry);
    case 'api': return execApi(flow, n, ctx, dry);
    case 'send': {
      const scope = flowScope(ctx);
      const msgs = c.repeat ? buildRepeat(c, scope) : [{ text: renderTpl(c.text, scope), image: c.image, buttons: c.buttons }];
      if (!msgs) return { next: n.next, log: `Daftar "${c.repeat.path}" kosong, pesan dilewati.` };
      if (!windowOpen(ctx.conv)) return { next: n.next, ok: false, log: 'Tidak dikirim: di luar jendela layanan 24 jam.' };
      const label = msgs.length > 1 ? `${msgs.length} pesan` : 'pesan';
      if (dry) return { next: n.next, action: true, log: 'Mengirim ' + label, previews: msgs };
      for (let i = 0; i < msgs.length; i++) {
        const err = await flowSendText(flow, n, ctx, msgs[i]);
        if (err) return { next: n.next, ok: false, action: i > 0, log: `Gagal mengirim${msgs.length > 1 ? ` pesan ${i + 1}/${msgs.length}` : ''}: ${err}` };
      }
      return { next: n.next, action: true, log: `${label[0].toUpperCase() + label.slice(1)} terkirim ke Meta` };
    }
    case 'assign': {
      const cur = ctx.conv.assignedTo ? byId('users', ctx.conv.assignedTo) : null;
      if (c.onlyIfUnassigned && cur) return { next: n.next, log: `Dilewati: sudah ditugaskan ke ${cur.name}.` };
      const target = pickAgent(flow, c);
      if (!target) return { next: n.next, ok: false, log: 'Tidak ada agen aktif.' };
      if (dry) { ctx.conv.assignedTo = target.id; return { next: n.next, action: true, log: `Diteruskan ke ${target.name}` }; }
      const conv = ctx.conv, prevId = conv.assignedTo;
      if (c.mode === 'round_robin') flow.rr = (flow.rr || 0) + 1;
      conv.assignedTo = target.id;
      if (conv.status === 'closed') conv.status = 'open';
      conv.notes = conv.notes || [];
      conv.notes.push({ id: uid('n_'), text: `Ditugaskan otomatis ke ${target.name} oleh flow "${flow.name}".`, userId: null, userName: 'Flow otomatis', at: now() });
      // Hapus dari daftar pengguna yang kini tidak berhak melihat percakapan
      if (prevId && prevId !== target.id) io?.to('user:' + prevId).emit('conversation:removed', { id: conv.id });
      if (!prevId) io?.to('agents').except('user:' + target.id).emit('conversation:removed', { id: conv.id });
      emitConv(conv, 'conversation:update', serializeConv(conv));
      notifyAssigned(conv, target, { name: `Flow "${flow.name}"` });
      audit(null, 'flow.assign', `${flow.name}: ${ctx.contact.phone} → ${target.name}`);
      return { next: n.next, action: true, log: `Diteruskan ke ${target.name}` };
    }
    case 'label': {
      const labels = ctx.contact.labels || [];
      const has = labels.includes(c.label);
      if (c.remove ? !has : has) return { next: n.next, log: `Label "${c.label}" ${c.remove ? 'tidak ada' : 'sudah ada'}.` };
      ctx.contact.labels = c.remove ? labels.filter((l) => l !== c.label) : cleanLabels([...labels, c.label]);
      if (!dry) { ctx.contact.updatedAt = now(); emitConv(ctx.conv, 'conversation:update', serializeConv(ctx.conv)); }
      return { next: n.next, action: true, log: `${c.remove ? 'Hapus' : 'Tambah'} label "${c.label}"` };
    }
    case 'status': {
      if (ctx.conv.status === c.status) return { next: n.next, log: `Status sudah ${STATUS_LABEL[c.status]}.` };
      ctx.conv.status = c.status;
      if (!dry) {
        emitConv(ctx.conv, 'conversation:update', serializeConv(ctx.conv));
        if (c.status === 'closed') maybeSendCsat(ctx.conv, 'flow', null);
      }
      return { next: n.next, action: true, log: `Status → ${STATUS_LABEL[c.status]}` };
    }
    case 'note': {
      const text = renderTpl(c.text, flowScope(ctx));
      if (!dry) {
        ctx.conv.notes = ctx.conv.notes || [];
        ctx.conv.notes.push({ id: uid('n_'), text, userId: null, userName: 'Flow: ' + flow.name, at: now() });
        emitConv(ctx.conv, 'conversation:update', serializeConv(ctx.conv));
      }
      return { next: n.next, action: true, log: 'Catatan internal ditambahkan', preview: { note: text } };
    }
    case 'delay': return { next: n.next, wait: c.minutes * 60000, log: `Tunggu ${fmtMinutes(c.minutes)}` };
    default: return { next: null, ok: false, log: 'Langkah tidak dikenal.' };
  }
}
const fmtMinutes = (m) => (m % 60 ? (m > 60 ? `${Math.floor(m / 60)} jam ${m % 60} menit` : `${m} menit`) : `${m / 60} jam`);

// Jalankan dari langkah startId sampai selesai, bertemu "Tunggu", atau menunggu jawaban pelanggan.
// dry: "Tunggu" dilewati dan hanya dicatat; "Tanya pelanggan" memakai jawaban uji.
async function execFlow(flow, run, ctx, startId, dry) {
  run.status = 'running'; run.runningSince = now();
  let id = startId, guard = 0;
  while (id && guard++ <= FLOW_MAX_NODES) {
    const n = flow.nodes[id];
    if (!n) break;
    const r = await execFlowNode(flow, n, ctx, dry);
    run.steps.push({ nodeId: id, type: n.type, at: now(), ok: r.ok !== false, log: r.log, ...(r.preview ? { preview: r.preview } : {}), ...(r.previews ? { previews: r.previews } : {}), ...(r.branch ? { branch: r.branch } : {}) });
    if (run.steps.length > 80) run.steps.splice(1, run.steps.length - 80); // run tanya-jawab yang panjang
    if (r.action) run.actions++;
    if (r.ok === false) run.error = r.log;
    if (r.wait && !dry) {
      Object.assign(run, { status: 'waiting', resumeAt: now() + r.wait, resumeNode: r.next, waitSince: now(), cancelOnReply: n.cfg.cancelOnReply, vars: ctx.vars });
      return run;
    }
    if (r.waitInput && !dry) {
      Object.assign(run, { status: 'input', input: r.waitInput, vars: ctx.vars });
      return run;
    }
    if (r.stop) { run.status = 'input'; return run; } // simulasi: tidak ada jawaban uji lagi
    if (r.cancelled) { run.status = 'cancelled'; break; }
    id = r.next;
  }
  if (run.status === 'running') run.status = run.error && !run.actions ? 'failed' : 'done';
  run.finishedAt = now();
  delete run.vars; delete run.input; // variabel (mis. respons API) tidak disimpan setelah run selesai
  return run;
}

function pushFlowRun(run) {
  db.flowRuns.push(run);
  if (db.flowRuns.length > FLOW_RUNS_MAX) {
    const drop = db.flowRuns.length - FLOW_RUNS_MAX;
    let removed = 0;
    db.flowRuns = db.flowRuns.filter((r) => (removed < drop && !FLOW_ACTIVE_RUN.includes(r.status) ? (removed++, false) : true));
  }
}
function finishFlowRun(flow, run) {
  flow.stats.runs++; flow.stats.actions += run.actions; flow.stats.lastRunAt = now();
  if (run.error) flow.stats.lastError = { at: now(), message: run.error };
  save();
  io?.to('admins').emit('flow:run', { flowId: flow.id, runId: run.id, status: run.status });
}
const lastHumanReplyAt = (conv) => {
  for (let i = db.messages.length - 1; i >= 0; i--) {
    const m = db.messages[i];
    if (m.conversationId === conv.id && m.direction === 'out' && m.userId) return m.timestamp;
  }
  return 0;
};
// Alasan flow tidak dijalankan untuk percakapan ini (null = boleh jalan)
function flowGate(flow, conv, at) {
  const s = flow.settings, today = zonedDate(flowTz(), at);
  if (s.activeFrom && today < s.activeFrom) return `Flow baru aktif mulai ${s.activeFrom}.`;
  if (s.activeUntil && today > s.activeUntil) return `Masa aktif flow berakhir ${s.activeUntil}.`;
  const human = lastHumanReplyAt(conv);
  if (s.pauseIfHumanMin && human && at - human < s.pauseIfHumanMin * 60000) return `CS membalas dalam ${s.pauseIfHumanMin} menit terakhir.`;
  if (s.cooldownMin && at - (conv.flowLog?.[flow.id] || 0) < s.cooldownMin * 60000) return `Flow sudah berjalan untuk percakapan ini dalam ${s.cooldownMin} menit terakhir.`;
  if (db.flowRuns.some((r) => FLOW_ACTIVE_RUN.includes(r.status) && r.flowId === flow.id && r.conversationId === conv.id)) return 'Flow masih menunggu (Tunggu / Tanya pelanggan) di percakapan ini.';
  return null;
}
function cancelFlowRuns(pred, reason) {
  let n = 0;
  for (const r of db.flowRuns) if (FLOW_ACTIVE_RUN.includes(r.status) && pred(r)) { r.status = 'cancelled'; r.error = reason; r.finishedAt = now(); delete r.vars; delete r.input; n++; }
  if (n) save();
  return n;
}

async function runFlows(conv, contact, msg, prevInboundAt) {
  const at = now(), text = inboundText(msg);
  // Run percakapan ini sedang diproses (mis. menunggu respons API): pesan beruntun tidak memulai flow lain
  if (db.flowRuns.some((r) => r.status === 'running' && r.conversationId === conv.id && at - (r.runningSince || 0) < 60000)) return true;
  // 1. Flow yang sedang menunggu jawaban di percakapan ini mendapat pesan ini lebih dulu
  const pending = db.flowRuns.filter((r) => r.status === 'input' && r.conversationId === conv.id).pop();
  if (pending) {
    const flow = byId('flows', pending.flowId), state = pending.input, node = flow?.nodes[state.nodeId];
    const end = (status, error) => { Object.assign(pending, { status, error, finishedAt: now() }); delete pending.vars; delete pending.input; save(); };
    const resume = async () => {
      const ctx = { conv, contact, text, msgType: msg.type, prevInboundAt: pending.prevInboundAt, at, clock: zonedNow(flowTz(), at),
        contextId: msg.wamid, vars: pending.vars || {}, answer: { msg, state } };
      delete pending.input;
      await execFlow(flow, pending, ctx, node.id, false);
      finishFlowRun(flow, pending);
    };
    if (!flow?.enabled) end('cancelled', 'Flow dinonaktifkan atau dihapus.');
    else if (!node || node.type !== (state.kind === 'flow' ? 'waflow' : 'ask')) end('cancelled', 'Langkah yang ditunggu sudah dihapus.');
    else if (state.kind === 'flow') {
      // Menunggu formulir: hanya jawaban dengan flow_token yang sama yang melanjutkan flow; pesan lain diproses seperti biasa
      if (msg.type === 'flow_reply' && msg.content.token === state.token && state.expiresAt >= at) { await resume(); return true; }
      if (flow.settings.cancelWords?.includes(text.trim().toLowerCase())) {
        end('cancelled', 'Dibatalkan pelanggan.');
        await sendAutoContent(conv, contact, { text: renderTpl(flow.settings.cancelText, { name: contact.name || contact.waName || 'Kak' }), image: null, buttons: [] },
          { auto: 'flow', userName: 'Flow: ' + flow.name, source: 'flow', btnPrefix: 'fl', flowId: flow.id }).catch((e) => console.warn('[flow]', e.message));
        return true;
      }
    }
    else if (lastHumanReplyAt(conv) > state.since) end('cancelled', 'CS mengambil alih percakapan.');
    else if (state.expiresAt < at) end('expired', `Pelanggan tidak menjawab dalam ${fmtMinutes(node.cfg.timeoutMinutes)}.`); // pesan ini diproses sebagai pesan baru
    else { await resume(); return true; }
  }
  // 2. Flow aktif dicek berurutan
  const flows = db.flows.filter((f) => f.enabled).sort((a, b) => a.order - b.order);
  // Pesan baru dari pelanggan membatalkan langkah "Tunggu" yang diatur batal bila dibalas
  cancelFlowRuns((r) => r.status === 'waiting' && r.conversationId === conv.id && r.cancelOnReply, 'Pelanggan mengirim pesan baru.');
  if (!flows.length) return false;
  for (const flow of flows) {
    if (flowGate(flow, conv, at)) continue;
    const ctx = { conv, contact, text, msgType: msg.type, prevInboundAt, at, clock: zonedNow(flowTz(), at), contextId: msg.wamid, vars: {} };
    const run = { id: uid('fr_'), flowId: flow.id, flowName: flow.name, conversationId: conv.id, contactId: contact.id, phone: contact.phone,
      text: text.slice(0, 300), msgType: msg.type, prevInboundAt, startedAt: at, status: 'running', steps: [], actions: 0, error: null };
    // Tandai sebelum aksi asinkron agar pesan beruntun tidak menjalankan flow (ber-jeda) dua kali
    const prevLog = conv.flowLog?.[flow.id];
    conv.flowLog = { ...conv.flowLog, [flow.id]: at };
    await execFlow(flow, run, ctx, flow.root, false);
    if (!run.actions && !FLOW_ACTIVE_RUN.includes(run.status)) {
      if (prevLog) conv.flowLog[flow.id] = prevLog; else delete conv.flowLog[flow.id];
      if (!run.error) continue; // tidak ada cabang yang cocok: coba flow berikutnya tanpa mencatat
    }
    pushFlowRun(run); finishFlowRun(flow, run);
    if (run.actions || FLOW_ACTIVE_RUN.includes(run.status)) return true;
  }
  return false;
}

// Worker: lanjutkan langkah "Tunggu" yang sudah jatuh tempo
let flowWorkerBusy = false;
setInterval(async () => {
  if (flowWorkerBusy) return;
  // Pertanyaan yang tidak dijawab sampai batas waktu, dan run yang macet (mis. server restart saat memanggil API)
  let changed = false;
  const formTimeouts = [];
  for (const r of db.flowRuns) {
    if (r.status === 'input' && r.input?.expiresAt < now()) {
      if (r.input.kind === 'flow') { formTimeouts.push(r); continue; } // formulir: jalankan cabang "Tidak diisi"
      Object.assign(r, { status: 'expired', error: 'Pelanggan tidak menjawab sampai batas waktu.', finishedAt: now() }); delete r.vars; delete r.input; changed = true;
    }
    else if (r.status === 'running' && now() - (r.runningSince || 0) > 5 * 60000) { Object.assign(r, { status: 'failed', error: 'Run terhenti (server dimulai ulang saat berjalan).', finishedAt: now() }); delete r.vars; changed = true; }
  }
  if (changed) save();
  const due = db.flowRuns.filter((r) => r.status === 'waiting' && r.resumeAt <= now());
  if (!due.length && !formTimeouts.length) return;
  flowWorkerBusy = true;
  try {
    for (const run of formTimeouts) {
      const flow = byId('flows', run.flowId), conv = byId('conversations', run.conversationId), contact = byId('contacts', run.contactId);
      const state = run.input, node = flow?.nodes[state.nodeId];
      if (!flow?.enabled || !conv || !contact || node?.type !== 'waflow') { Object.assign(run, { status: 'expired', error: 'Formulir tidak diisi sampai batas waktu.', finishedAt: now() }); delete run.vars; delete run.input; save(); continue; }
      const ctx = { conv, contact, text: run.text, msgType: run.msgType, prevInboundAt: run.prevInboundAt, at: now(), clock: zonedNow(flowTz()), contextId: null,
        vars: run.vars || {}, answer: { msg: null, state }, timedOut: true };
      delete run.input;
      await execFlow(flow, run, ctx, node.id, false);
      finishFlowRun(flow, run);
    }
    for (const run of due) {
      const flow = byId('flows', run.flowId), conv = byId('conversations', run.conversationId), contact = byId('contacts', run.contactId);
      const stop = (reason) => { run.status = 'cancelled'; run.error = reason; run.finishedAt = now(); delete run.vars; save(); };
      if (!flow || !flow.enabled) { stop('Flow dinonaktifkan atau dihapus.'); continue; }
      if (!conv || !contact) { stop('Percakapan atau kontak sudah dihapus.'); continue; }
      if (run.cancelOnReply && lastHumanReplyAt(conv) > run.waitSince) { stop('CS sudah membalas.'); continue; }
      const ctx = { conv, contact, text: run.text, msgType: run.msgType, prevInboundAt: run.prevInboundAt, at: now(), clock: zonedNow(flowTz()), contextId: null, vars: run.vars || {} };
      await execFlow(flow, run, ctx, run.resumeNode, false);
      finishFlowRun(flow, run);
    }
  } catch (e) { console.warn('[flow-worker]', e.message); }
  finally { flowWorkerBusy = false; }
}, 15000);

// Simulasi tanpa mengirim apa pun: kontak & percakapan tiruan
async function testFlow(flow, b) {
  const at = now(), z = zonedNow(flowTz(), at);
  const day = Number.isInteger(Number(b.day)) && b.day !== '' && b.day != null ? Number(b.day) : z.day;
  const time = /^([01]\d|2[0-3]):[0-5]\d$/.test(b.time || '') ? b.time : z.time;
  const contact = { name: 'Budi', waName: 'Budi', phone: '6281234567890', labels: cleanLabels(b.labels) };
  const conv = { id: 'test', status: 'open', assignedTo: b.assigned ? flowAgents()[0]?.id || 'x' : null, lastInboundAt: at, notes: [] };
  const msgType = FLOW_MSG_TYPES.includes(b.msgType) ? (b.msgType === 'reply' ? 'interactive_reply' : b.msgType) : 'text';
  const ctx = { conv, contact, text: str(b.text, 1000), msgType, prevInboundAt: b.newContact ? 0 : at - 3600000, at, clock: { day, time }, contextId: null, vars: {},
    dryAnswers: (Array.isArray(b.answers) ? b.answers : String(b.answers || '').split('\n')).map((x) => str(String(x), 500)).filter(Boolean).slice(0, 10),
    liveApi: b.liveApi !== false };
  const run = { steps: [], actions: 0, error: null };
  await execFlow({ ...flow, rr: flow.rr || 0 }, run, ctx, flow.root, true);
  // Variabel akhir untuk membantu penyusunan template (objek besar dipotong)
  const vars = Object.fromEntries(Object.entries(ctx.vars).map(([k, v]) => [k, v && typeof v === 'object' ? JSON.stringify(v).slice(0, 400) : v]));
  return { steps: run.steps, actions: run.actions, clock: { day, time }, vars, waitingAnswer: run.status === 'input' };
}
function flowUsesImage(key) {
  return db.flows.some((f) => Object.values(f.nodes).some((n) => n.type === 'send' && n.cfg.image === key));
}

function handleStatuses(value) {
  for (const s of value.statuses || []) {
    const msg = idx.wamid.get(s.id);
    if (msg) {
      recordStatus(msg, s); // riwayat lengkap untuk Log pesan (duplikat diabaikan)
      const ok = s.status === 'failed' || (STATUS_RANK[s.status] ?? -1) > (STATUS_RANK[msg.status] ?? -1);
      if (ok) {
        msg.status = s.status;
        if (s.status === 'failed') msg.error = (s.errors || []).map((e) => `${e.title || e.message} (${e.code})${e.error_data?.details ? ': ' + e.error_data.details : ''}`).join('; ');
        msg.statusAt = Number(s.timestamp) * 1000 || now();
      }
      if (s.pricing) msg.pricing = { category: String(s.pricing.category || '').toLowerCase(), billable: !!s.pricing.billable, model: s.pricing.pricing_model, type: s.pricing.type || null, at: msg.pricing?.at || Number(s.timestamp) * 1000 || now() };
      const conv = byId('conversations', msg.conversationId);
      if (conv) emitConv(conv, 'message:update', { message: msg });
      if (msg.groupId) io?.to('admins').emit('group:message', { groupId: msg.groupId, message: msg });
    } else if (s.id) {
      // Pesan dikirim di luar Kontaq (aplikasi lain / WhatsApp Manager) dengan nomor yang sama: isi tidak diketahui,
      // tetapi status dan biayanya tetap dicatat agar total pengiriman lengkap.
      let entry = logByWamid.get(s.id);
      if (!entry) {
        const contact = idx.contactByPhone.get(normPhone(s.recipient_id));
        entry = pushLog({
          id: uid('l_'), at: Number(s.timestamp) * 1000 || now(), source: 'external', userId: null, userName: '', campaignId: null, campaignName: '',
          contactId: contact?.id || null, conversationId: contact ? idx.convByContact.get(contact.id)?.id || null : null, to: normPhone(s.recipient_id),
          type: 'unknown', summary: '', templateName: '', templateLanguage: '', templateCategory: s.pricing?.category || '',
          phoneNumberId: value.metadata?.phone_number_id || meta().phoneNumberId, wabaId: meta().wabaId, graphVersion: '',
          request: null, ok: true, http: null, response: null, error: null, wamid: s.id, statuses: [],
        });
      }
      recordStatus(entry, s);
      if (s.pricing) entry.pricing = { category: String(s.pricing.category || '').toLowerCase(), billable: !!s.pricing.billable, model: s.pricing.pricing_model, type: s.pricing.type || null };
    }
    // Laporan campaign
    for (const camp of db.campaigns) {
      if (camp.status === 'draft') continue;
      const r = camp.recipients.find((x) => x.wamid === s.id);
      if (!r) continue;
      if (s.status === 'failed' || (STATUS_RANK[s.status] ?? -1) > (STATUS_RANK[r.status] ?? -1)) {
        r.status = s.status;
        if (s.status === 'failed') r.error = (s.errors || []).map((e) => `${e.title || e.message} (${e.code})`).join('; ');
      }
      io?.to('admins').emit('campaign:update', campaignSummary(camp));
      break;
    }
  }
  save();
}

/* ── Grup WhatsApp (Groups API) ──
 * Hanya untuk Official Business Account (OBA). Grup hanya-undangan, maks. 8 peserta.
 * Buat/hapus/ubah pengaturan/keluarkan peserta bersifat asinkron: API mengembalikan request_id, hasil akhirnya datang
 * lewat webhook (group_lifecycle_update, group_settings_update, group_participants_update). Status di Kontaq baru
 * diubah setelah webhook tersebut tiba — permintaan yang diterima API belum dianggap berhasil.
 * Peserta tidak dapat ditambahkan langsung: bergabung lewat tautan undangan atau permintaan bergabung yang disetujui.
 */
const GROUP_MAX_PARTICIPANTS = 8;
const GROUP_EVENTS_MAX = 200;
const GROUP_SEND_TYPES = ['text', 'image', 'video', 'audio', 'document'];
const GROUP_FIELDS = ['group_lifecycle_update', 'group_participants_update', 'group_settings_update', 'group_status_update'];

const groupByMeta = (gid) => (gid ? db.groups.find((g) => g.groupId === String(gid)) : null);
const groupOr404 = (id) => { const g = byId('groups', id); if (!g) throw new HttpError(404, 'Grup tidak ditemukan.'); return g; };
const metaErrText = (errs) => (errs || []).map((e) => `${e.title || e.message} (${e.code})${e.error_data?.details ? ': ' + e.error_data.details : ''}`).join('; ');
const samePerson = (p, key) => !!key && (p.waId === key || p.phone === normPhone(key));
function newGroup(data) {
  return { id: uid('g_'), groupId: null, requestId: null, subject: '', description: '', joinApprovalMode: 'auto_approve', inviteLink: null,
    status: 'creating', error: null, suspended: false, participants: [], joinRequests: [], invites: [], pending: {}, events: [],
    photo: null, unread: 0, lastMessageAt: 0, preview: '', createdAt: now(), createdBy: null, external: false, ...data };
}
function groupEvent(g, type, text) {
  g.events.unshift({ at: now(), type, text: String(text).slice(0, 500) });
  if (g.events.length > GROUP_EVENTS_MAX) g.events.length = GROUP_EVENTS_MAX;
}
const groupSummary = (g) => {
  const { events, invites, photo, ...rest } = g;
  return { ...rest, hasPhoto: !!photo?.data, photoStatus: photo?.status || null, photoAt: photo?.at || 0, inviteCount: invites.length };
};
function emitGroup(g) { io?.to('admins').emit('group:update', groupSummary(g)); }
// Grup yang dibuat di luar Kontaq dengan nomor yang sama: buat catatan agar event-nya tetap terekam
function ensureGroup(gid, ev) {
  let g = groupByMeta(gid);
  if (!g) {
    g = newGroup({ groupId: String(gid), subject: ev?.subject || '(Grup tanpa nama)', status: 'active', external: true });
    db.groups.push(g);
    groupEvent(g, 'import', 'Grup tercatat dari webhook (dibuat di luar Kontaq atau sebelum fitur ini).');
  }
  return g;
}
function addParticipant(g, p, via) {
  const waId = String(p.wa_id || ''), phone = normPhone(p.input || p.wa_id);
  if (!waId && !phone) return null;
  let row = g.participants.find((x) => samePerson(x, waId) || samePerson(x, phone));
  if (!row) { row = { waId: waId || phone, phone: phone || waId, joinedAt: now(), via }; g.participants.push(row); }
  g.joinRequests = g.joinRequests.filter((r) => !samePerson({ waId: r.waId, phone: normPhone(r.waId) }, waId));
  // Pantau undangan: tandai undangan ke nomor ini sebagai sudah bergabung
  for (const inv of g.invites) if (!inv.joinedAt && (inv.phone === row.phone || inv.phone === normPhone(waId))) inv.joinedAt = now();
  return row;
}
const personLabel = (key) => {
  const c = idx.contactByPhone.get(normPhone(key));
  return c ? `${c.name || c.waName || 'Kontak'} (+${c.phone})` : '+' + normPhone(key);
};

function handleGroupWebhook(field, value) {
  for (const ev of value.groups || []) {
    const errs = metaErrText(ev.errors);
    switch (ev.type) {
      case 'group_create': {
        // Cocokkan dengan request_id; cadangan: grup "creating" terbaru dengan nama yang sama
        let g = db.groups.find((x) => ev.request_id && x.requestId === ev.request_id)
          || groupByMeta(ev.group_id)
          || db.groups.filter((x) => x.status === 'creating' && x.subject === ev.subject).pop();
        if (!g) { g = newGroup({ subject: ev.subject || '(Grup tanpa nama)', external: true }); db.groups.push(g); }
        if (errs) { g.status = 'failed'; g.error = errs; groupEvent(g, 'create_failed', 'Gagal membuat grup: ' + errs); break; }
        Object.assign(g, { groupId: String(ev.group_id), status: 'active', error: null, inviteLink: ev.invite_link || g.inviteLink,
          joinApprovalMode: ev.join_approval_mode || g.joinApprovalMode, subject: ev.subject || g.subject });
        groupEvent(g, 'created', 'Grup berhasil dibuat oleh Meta.');
        break;
      }
      case 'group_delete': {
        const g = groupByMeta(ev.group_id);
        if (!g) break;
        if (errs) { g.status = g.suspended ? 'suspended' : 'active'; g.error = errs; groupEvent(g, 'delete_failed', 'Gagal menghapus grup: ' + errs); break; }
        Object.assign(g, { status: 'deleted', inviteLink: null, participants: [], joinRequests: [], error: null });
        groupEvent(g, 'deleted', 'Grup dihapus. Semua peserta dikeluarkan.');
        break;
      }
      case 'group_participants_add': {
        const g = ensureGroup(ev.group_id, ev);
        const via = ev.reason === 'invite_link' ? 'tautan undangan' : ev.reason || 'undangan';
        for (const p of ev.added_participants || []) if (addParticipant(g, p, via)) groupEvent(g, 'join', `${personLabel(p.input || p.wa_id)} bergabung lewat ${via}.`);
        break;
      }
      case 'group_participants_remove': {
        const g = ensureGroup(ev.group_id, ev);
        for (const p of ev.removed_participants || []) {
          const key = p.wa_id || p.input;
          g.participants = g.participants.filter((x) => !samePerson(x, key));
          groupEvent(g, 'leave', ev.initiated_by === 'participant' ? `${personLabel(key)} keluar dari grup.` : `${personLabel(key)} dikeluarkan dari grup.`);
        }
        for (const p of ev.failed_participants || []) groupEvent(g, 'remove_failed', `Gagal mengeluarkan ${personLabel(p.input || p.wa_id)}: ${metaErrText(p.errors) || errs}`);
        delete g.pending.remove;
        if (errs && !(ev.failed_participants || []).length) g.error = errs;
        break;
      }
      case 'group_join_request_created': {
        const g = ensureGroup(ev.group_id, ev);
        if (!g.joinRequests.some((r) => r.id === ev.join_request_id)) g.joinRequests.push({ id: String(ev.join_request_id), waId: String(ev.wa_id || ''), at: Number(ev.timestamp) * 1000 || now() });
        groupEvent(g, 'join_request', `${personLabel(ev.wa_id)} meminta bergabung.`);
        break;
      }
      case 'group_join_request_revoked': {
        const g = ensureGroup(ev.group_id, ev);
        g.joinRequests = g.joinRequests.filter((r) => r.id !== String(ev.join_request_id));
        groupEvent(g, 'join_request_revoked', `Permintaan bergabung ${personLabel(ev.wa_id)} ditarik.`);
        break;
      }
      case 'group_settings_update': {
        const g = ensureGroup(ev.group_id, ev);
        const parts = [];
        const apply = (src, key, label) => {
          if (!src) return;
          if (src.update_successful) { if (key) g[key] = src.text ?? g[key]; parts.push(`${label} diperbarui`); }
          else parts.push(`${label} gagal: ${metaErrText(src.errors) || 'ditolak Meta'}`);
        };
        apply(ev.group_subject, 'subject', 'Nama grup');
        apply(ev.group_description, 'description', 'Deskripsi');
        if (ev.profile_picture) {
          apply(ev.profile_picture, null, 'Foto grup');
          if (g.photo) g.photo.status = ev.profile_picture.update_successful ? 'ok' : 'failed';
        }
        g.pending = {};
        g.error = parts.some((p) => p.includes('gagal')) ? parts.filter((p) => p.includes('gagal')).join('; ') : null;
        groupEvent(g, 'settings', parts.join(' · ') || 'Pengaturan diperbarui.');
        break;
      }
      case 'group_suspend': {
        const g = ensureGroup(ev.group_id, ev);
        Object.assign(g, { suspended: true, status: 'suspended' });
        groupEvent(g, 'suspended', 'Grup ditangguhkan oleh WhatsApp. Pesan tidak dapat dikirim.');
        break;
      }
      case 'group_suspend_cleared': {
        const g = ensureGroup(ev.group_id, ev);
        Object.assign(g, { suspended: false, status: 'active' });
        groupEvent(g, 'suspend_cleared', 'Penangguhan grup dicabut.');
        break;
      }
      default: continue;
    }
    const g = groupByMeta(ev.group_id) || db.groups.find((x) => ev.request_id && x.requestId === ev.request_id);
    if (g) emitGroup(g);
  }
  save();
}

function handleGroupMessage(m, profiles) {
  const g = ensureGroup(m.group_id);
  if (m.type === 'reaction') {
    const target = idx.wamid.get(m.reaction?.message_id);
    if (target?.groupId === g.id) { target.reaction = m.reaction.emoji || null; save(); io?.to('admins').emit('group:message', { groupId: g.id, message: target }); }
    return;
  }
  const { type, content } = parseInbound(m);
  const from = normPhone(m.from);
  // Pengirim pasti anggota; catat bila belum ada (mis. grup lama sebelum sinkronisasi)
  if (from && !g.participants.some((p) => samePerson(p, from))) g.participants.push({ waId: from, phone: from, joinedAt: 0, via: 'terdeteksi dari pesan' });
  const msg = { id: uid('m_'), groupId: g.id, direction: 'in', type, content, wamid: m.id, status: 'received', timestamp: Number(m.timestamp) * 1000 || now(),
    from, fromName: profiles[m.from] || idx.contactByPhone.get(from)?.name || '', contextId: m.context?.id || null };
  db.messages.push(msg); idx.wamid.set(msg.wamid, msg);
  g.lastMessageAt = msg.timestamp; g.unread = (g.unread || 0) + 1;
  g.preview = `${msg.fromName || '+' + from}: ${String(previewOf(msg) || '').slice(0, 120)}`;
  save();
  io?.to('admins').emit('group:message', { groupId: g.id, message: msg, group: groupSummary(g) });
}

// Kirim pesan ke grup. Pesan yang gagal tetap dicatat (status failed + error) agar terlihat di riwayat grup.
async function sendToGroup(g, b, user) {
  if (g.status !== 'active' || !g.groupId) throw new HttpError(400, g.status === 'suspended' ? 'Grup sedang ditangguhkan WhatsApp.' : 'Grup belum aktif (menunggu konfirmasi Meta) atau sudah dihapus.');
  const type = str(b.type, 40);
  let payload, record;
  if (type === 'template') {
    const tpl = findTemplate(str(b.name, 512), str(b.language, 15));
    if (!tpl) throw new HttpError(400, 'Template tidak ditemukan. Sinkronkan template terlebih dahulu.');
    if (tpl.status !== 'APPROVED') throw new HttpError(400, `Template berstatus ${tpl.status}, hanya APPROVED yang dapat dikirim.`);
    const components = buildTemplateComponents(tpl, b.values || {}, {});
    payload = { type: 'template', template: { name: tpl.name, language: { code: tpl.language }, ...(components.length ? { components } : {}) } };
    record = { type: 'template', content: { name: tpl.name, language: tpl.language, body: renderTemplateText(tpl, components) } };
  } else {
    if (!GROUP_SEND_TYPES.includes(type)) throw new HttpError(400, 'Grup mendukung pesan teks, media, dan template.');
    const built = buildOutbound(type, b);
    payload = { type, ...built.payload };
    record = { type, content: built.content };
  }
  const full = { messaging_product: 'whatsapp', recipient_type: 'group', to: g.groupId, ...payload };
  if (b.replyTo) { const ctx = byId('messages', b.replyTo); if (ctx?.groupId === g.id && ctx.wamid) full.context = { message_id: ctx.wamid }; }
  const msg = { id: uid('m_'), groupId: g.id, direction: 'out', ...record, status: 'pending', timestamp: now(), userId: user.id, userName: user.name, contextId: full.context?.message_id || null };
  try {
    const r = await sendToMeta(full, { source: 'group', userId: user.id, userName: user.name, template: type === 'template' ? findTemplate(b.name, b.language) : null });
    Object.assign(msg, { wamid: r.messages?.[0]?.id || null, status: 'accepted' });
  } catch (e) {
    Object.assign(msg, { status: 'failed', error: e.message });
    throw Object.assign(e, { groupMessage: msg });
  } finally {
    db.messages.push(msg);
    if (msg.wamid) idx.wamid.set(msg.wamid, msg);
    g.lastMessageAt = msg.timestamp; g.preview = 'Anda: ' + String(previewOf(msg) || '').slice(0, 120);
    save();
    io?.to('admins').emit('group:message', { groupId: g.id, message: msg, group: groupSummary(g) });
  }
  return msg;
}

/* ── CSAT (survei kepuasan pelanggan) ──
 * Dikirim saat percakapan ditutup (oleh agen, opsional oleh flow) atau manual dari inbox, hanya bila jendela layanan
 * 24 jam masih terbuka. Skala 5 memakai pesan daftar (list), skala 3 memakai tombol balasan.
 * Jawaban (interactive reply berawalan "csat_") dan komentar lanjutan tidak membuka kembali percakapan dan tidak memicu
 * flow/auto reply. CSAT % = jawaban "puas" (skala 5: nilai 4–5; skala 3: Puas) ÷ jumlah jawaban.
 */
const CSAT_SURVEYS_MAX = 20000;
const CSAT_SCALES = {
  5: [[5, 'Sangat puas', '★★★★★'], [4, 'Puas', '★★★★☆'], [3, 'Cukup', '★★★☆☆'], [2, 'Kurang puas', '★★☆☆☆'], [1, 'Sangat kecewa', '★☆☆☆☆']],
  3: [[3, 'Puas'], [2, 'Biasa saja'], [1, 'Tidak puas']],
};
const csatSatisfied = (scale, score) => (Number(scale) === 3 ? score === 3 : score >= 4);
const csatScore5 = (scale, score) => (Number(scale) === 3 ? { 1: 1, 2: 3, 3: 5 }[score] : score); // rata-rata dinormalkan ke skala 5
function csatDefaults() {
  return {
    settings: {
      enabled: false, scale: 5, sendOnClose: true, sendOnFlowClose: false, onlyIfAgentReplied: true,
      question: 'Halo {{name}}, terima kasih telah menghubungi kami. Bagaimana penilaian Anda terhadap layanan kami?',
      button: 'Beri penilaian', footer: 'Survei singkat, cukup satu ketukan',
      askComment: true, commentPrompt: 'Terima kasih atas penilaiannya! Ada masukan agar kami bisa lebih baik? Silakan balas pesan ini (opsional).',
      thanks: 'Terima kasih, masukan Anda sangat berarti bagi kami 🙏', commentMinutes: 30, expireHours: 24, cooldownHours: 24,
    },
    surveys: [],
  };
}
const csatCfg = () => (db.csat = db.csat || csatDefaults());
function validateCsat(b) {
  const prev = csatCfg().settings;
  const num = (v, min, max, label) => { const n = Number(v); if (!Number.isInteger(n) || n < min || n > max) throw new HttpError(400, `${label} harus bilangan bulat ${min}–${max}.`); return n; };
  const text = (v, max, label, required = true) => { const t = str(v, max); if (required && !t) throw new HttpError(400, `${label} wajib diisi.`); return t; };
  const s = {
    enabled: !!b.enabled, scale: Number(b.scale) === 3 ? 3 : 5,
    sendOnClose: b.sendOnClose !== false, sendOnFlowClose: !!b.sendOnFlowClose, onlyIfAgentReplied: b.onlyIfAgentReplied !== false,
    question: text(b.question ?? prev.question, 1024, 'Pertanyaan survei'),
    button: text(b.button ?? prev.button, 20, 'Teks tombol daftar'),
    footer: text(b.footer ?? '', 60, 'Footer', false),
    askComment: !!b.askComment,
    commentPrompt: text(b.commentPrompt ?? prev.commentPrompt, 1024, 'Pesan permintaan masukan', !!b.askComment),
    thanks: text(b.thanks ?? prev.thanks, 1024, 'Pesan terima kasih'),
    commentMinutes: num(b.commentMinutes ?? 30, 1, 1440, 'Batas waktu masukan (menit)'),
    expireHours: num(b.expireHours ?? 24, 1, 24, 'Masa berlaku survei (jam)'),
    cooldownHours: num(b.cooldownHours ?? 24, 0, 720, 'Jeda survei per kontak (jam)'),
  };
  return s;
}
// Survei terakhir per percakapan (indeks in-memory; dibangun saat pertama dipakai)
let csatIdx = null;
const csatOf = (conv) => {
  if (!csatIdx) { csatIdx = new Map(); for (const x of csatCfg().surveys) csatIdx.set(x.conversationId, x); }
  return csatIdx.get(conv.id) || null;
};
const csatPush = (survey) => {
  const list = csatCfg().surveys;
  list.push(survey); csatOf({}); csatIdx.set(survey.conversationId, survey);
  if (list.length > CSAT_SURVEYS_MAX) list.splice(0, list.length - CSAT_SURVEYS_MAX);
};
const csatPublic = (x) => x && { id: x.id, status: x.status, score: x.score ?? null, scale: x.scale, comment: x.comment || '', sentAt: x.sentAt, answeredAt: x.answeredAt || 0, reason: x.reason || '' };

// Kirim survei. trigger: 'close' | 'flow' | 'manual'. Mengembalikan catatan survei (status sent / skipped / failed).
async function sendCsat(conv, { trigger, user }) {
  const cfg = csatCfg(), s = cfg.settings, contact = byId('contacts', conv.contactId);
  if (!contact) return null;
  const manual = trigger === 'manual', at = now();
  const last = cfg.surveys.slice().reverse().find((x) => x.contactId === contact.id && x.status !== 'skipped');
  let reason = null;
  if (!windowOpen(conv)) reason = 'Jendela layanan 24 jam sudah tertutup.';
  else if (last?.status === 'sent' && last.expiresAt > at) reason = 'Masih ada survei yang belum dijawab.';
  else if (!manual && s.cooldownHours && last && at - last.sentAt < s.cooldownHours * 3600000) reason = `Kontak sudah disurvei dalam ${s.cooldownHours} jam terakhir.`;
  else if (!manual && s.onlyIfAgentReplied && lastHumanReplyAt(conv) <= (csatOf(conv)?.sentAt || 0)) reason = 'Belum ada balasan agen sejak survei terakhir.';
  const agent = conv.assignedTo ? byId('users', conv.assignedTo) : null;
  const survey = { id: uid('cs').replace(/[^A-Za-z0-9]/g, '').slice(0, 14), conversationId: conv.id, contactId: contact.id, phone: contact.phone,
    agentId: agent?.id || null, agentName: agent?.name || '', scale: s.scale, trigger, by: user?.name || (trigger === 'flow' ? 'Flow' : 'Sistem'),
    sentAt: at, expiresAt: at + s.expireHours * 3600000, status: reason ? 'skipped' : 'sent', reason, score: null, comment: '', wamid: null };
  if (reason) {
    // Lewati tanpa mencatat untuk pemicu otomatis biasa (tidak menambah noise); catat bila diminta manual
    if (manual) throw new HttpError(400, 'Survei tidak dikirim: ' + reason);
    return survey;
  }
  const rows = CSAT_SCALES[s.scale];
  const body = fillVars(s.question, contact).slice(0, 1024);
  let interactive, record;
  if (s.scale === 5) {
    const list = rows.map(([score, title, desc]) => ({ id: `csat_${survey.id}_${score}`, title, description: desc }));
    interactive = { type: 'list', body: { text: body }, action: { button: s.button, sections: [{ title: 'Penilaian', rows: list }] } };
    record = { kind: 'list', header: '', body, footer: s.footer, button: s.button, rows: list.map((r) => ({ id: r.id, title: r.title, description: r.description })) };
  } else {
    interactive = { type: 'button', body: { text: body }, action: { buttons: rows.map(([score, title]) => ({ type: 'reply', reply: { id: `csat_${survey.id}_${score}`, title } })) } };
    record = { kind: 'button', header: '', body, footer: s.footer, buttons: rows.map((r) => r[1]) };
  }
  if (s.footer) interactive.footer = { text: s.footer };
  try {
    const r = await sendToMeta({ messaging_product: 'whatsapp', recipient_type: 'individual', to: contact.phone, type: 'interactive', interactive },
      { source: 'csat', contact, conversation: conv, userId: user?.id, userName: 'CSAT' });
    survey.wamid = r.messages?.[0]?.id || null;
    addMessage(conv, { direction: 'out', type: 'interactive', content: record, wamid: survey.wamid, status: 'accepted', userName: 'Survei CSAT', auto: 'csat' });
  } catch (e) {
    Object.assign(survey, { status: 'failed', reason: e.message });
    if (manual) { csatPush(survey); save(); throw e; }
  }
  csatPush(survey);
  save();
  emitConv(conv, 'conversation:update', serializeConv(conv));
  return survey;
}
function maybeSendCsat(conv, trigger, user) {
  const s = csatCfg().settings;
  if (!s.enabled || (trigger === 'close' && !s.sendOnClose) || (trigger === 'flow' && !s.sendOnFlowClose)) return;
  sendCsat(conv, { trigger, user }).catch((e) => console.warn('[csat]', e.message));
}
async function csatText(conv, contact, text) {
  try {
    const body = fillVars(text, contact).slice(0, 4096);
    const r = await sendToMeta({ messaging_product: 'whatsapp', recipient_type: 'individual', to: contact.phone, type: 'text', text: { body } },
      { source: 'csat', contact, conversation: conv, userName: 'CSAT' });
    addMessage(conv, { direction: 'out', type: 'text', content: { body }, wamid: r.messages?.[0]?.id, status: 'accepted', userName: 'Survei CSAT', auto: 'csat' });
  } catch (e) { console.warn('[csat]', e.message); }
}
// Tangani jawaban survei. true = pesan ini milik survei (jangan buka ulang percakapan / jalankan flow).
function handleCsatReply(conv, contact, msg) {
  const cfg = csatCfg(), s = cfg.settings;
  const m = msg.type === 'interactive_reply' && /^csat_([A-Za-z0-9]+)_([1-5])$/.exec(msg.content.id || '');
  if (m) {
    const survey = cfg.surveys.find((x) => x.id === m[1] && x.conversationId === conv.id);
    if (!survey) return false;
    if (survey.status === 'answered') return true; // jawaban ganda: abaikan
    const score = Number(m[2]);
    Object.assign(survey, { status: 'answered', score, satisfied: csatSatisfied(survey.scale, score), answeredAt: now(), late: now() > survey.expiresAt });
    if (s.askComment) survey.commentUntil = now() + s.commentMinutes * 60000;
    save();
    csatText(conv, contact, s.askComment ? s.commentPrompt : s.thanks);
    io?.to('admins').emit('csat:update', csatPublic(survey));
    return true;
  }
  if (msg.type === 'text') {
    const survey = csatOf(conv);
    if (survey?.status === 'answered' && !survey.comment && survey.commentUntil > now()) {
      Object.assign(survey, { comment: str(msg.content.body, 2000), commentAt: now(), commentUntil: 0 });
      save();
      csatText(conv, contact, s.thanks);
      io?.to('admins').emit('csat:update', csatPublic(survey));
      return true;
    }
  }
  return false;
}
// Survei yang tidak dijawab sampai masa berlakunya habis
setInterval(() => {
  let n = 0;
  for (const x of csatCfg().surveys) if (x.status === 'sent' && x.expiresAt < now()) { x.status = 'expired'; n++; }
  if (n) save();
}, 5 * 60000);

function csatReport({ from, to, agentId }) {
  const rows = csatCfg().surveys.filter((x) => x.sentAt >= from && x.sentAt < to && (!agentId || x.agentId === agentId) && x.status !== 'skipped');
  const delivered = rows.filter((x) => x.status !== 'failed');
  const answered = rows.filter((x) => x.status === 'answered');
  const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : null);
  const avg = (list) => (list.length ? Math.round((list.reduce((t, x) => t + csatScore5(x.scale, x.score), 0) / list.length) * 100) / 100 : null);
  const sum = (list) => ({ sent: list.filter((x) => x.status !== 'failed').length, answered: list.filter((x) => x.status === 'answered').length,
    csat: pct(list.filter((x) => x.satisfied).length, list.filter((x) => x.status === 'answered').length), avg: avg(list.filter((x) => x.status === 'answered')) });
  const dist = {};
  for (const x of answered) { const k = `${x.scale}:${x.score}`; dist[k] = (dist[k] || 0) + 1; }
  const agents = {};
  for (const x of rows) (agents[x.agentId || ''] = agents[x.agentId || ''] || { id: x.agentId, name: x.agentName || 'Belum ditugaskan', list: [] }).list.push(x);
  const days = Math.min(366, Math.ceil((to - from) / 86400000));
  const daily = Array.from({ length: days }, (_, i) => ({ t: from + i * 86400000, list: [] }));
  for (const x of answered) { const d = daily[Math.floor((x.sentAt - from) / 86400000)]; if (d) d.list.push(x); }
  return {
    from, to, ...sum(rows), responseRate: pct(answered.length, delivered.length), failed: rows.filter((x) => x.status === 'failed').length,
    expired: rows.filter((x) => x.status === 'expired').length, satisfied: answered.filter((x) => x.satisfied).length,
    distribution: dist,
    agents: Object.values(agents).map((a) => ({ id: a.id, name: a.name, ...sum(a.list) })).sort((a, b) => b.answered - a.answered),
    daily: daily.map((d) => ({ t: d.t, answered: d.list.length, csat: pct(d.list.filter((x) => x.satisfied).length, d.list.length) })),
    comments: answered.filter((x) => x.comment).slice(-50).reverse().map((x) => ({ ...csatPublic(x), agentName: x.agentName, contact: contactLabel(byId('contacts', x.contactId) || { phone: x.phone }), conversationId: x.conversationId })),
    recent: rows.slice(-100).reverse().map((x) => ({ ...csatPublic(x), agentName: x.agentName, trigger: x.trigger, contact: contactLabel(byId('contacts', x.contactId) || { phone: x.phone }), conversationId: x.conversationId })),
  };
}

/* ── WhatsApp Flows (Meta) ──
 * Formulir interaktif resmi WhatsApp. Flow dibuat & dikelola lewat Flows API ({WABA}/flows), dikirim sebagai pesan
 * interactive "flow" (dalam jendela 24 jam) atau template bertombol FLOW. Setiap pengiriman membawa flow_token unik;
 * jawaban (nfm_reply.response_json) dicocokkan lewat token tersebut. Kontaq mendukung flow tanpa endpoint
 * (navigate + complete). Flow ber-endpoint (data_exchange) memerlukan server endpoint terenkripsi milik Anda sendiri.
 */
const WAF_CATEGORIES = ['SIGN_UP', 'SIGN_IN', 'APPOINTMENT_BOOKING', 'LEAD_GENERATION', 'CONTACT_US', 'CUSTOMER_SUPPORT', 'SURVEY', 'OTHER'];
const WAF_FIELDS = 'id,name,status,categories,validation_errors,json_version,data_api_version,endpoint_uri';
const WAF_SUBMISSIONS_MAX = 20000;
const WAF_JSON_MAX = 1024 * 1024;
const wafById = (id) => (id ? db.waFlows.find((f) => f.id === String(id)) : null);
const newFlowToken = () => 'kq.' + crypto.randomBytes(12).toString('base64url');
// Screen dari Flow JSON (untuk memilih screen pertama saat mengirim)
function wafScreens(json) {
  try { return (JSON.parse(json || '{}').screens || []).map((s) => ({ id: String(s.id), title: String(s.title || s.id), terminal: !!s.terminal })).filter((s) => s.id); }
  catch { return []; }
}
function wafUpsert(x) {
  let f = wafById(x.id);
  if (!f) { f = { id: String(x.id), json: null, alerts: [], createdAt: now() }; db.waFlows.push(f); }
  Object.assign(f, {
    name: x.name ?? f.name, status: x.status ?? f.status, categories: x.categories ?? f.categories ?? [],
    validationErrors: x.validation_errors ?? f.validationErrors ?? [], jsonVersion: x.json_version ?? f.jsonVersion ?? null,
    endpointUri: x.endpoint_uri ?? f.endpointUri ?? null, syncedAt: now(),
  });
  return f;
}
const wafPublic = (f, full) => {
  const subs = wafSubmissions(f.id);
  return {
    id: f.id, name: f.name, status: f.status, categories: f.categories, validationErrors: f.validationErrors, jsonVersion: f.jsonVersion,
    endpointUri: f.endpointUri, syncedAt: f.syncedAt, alerts: (f.alerts || []).slice(0, 10), screens: wafScreens(f.json),
    sent: subs.length, completed: subs.filter((s) => s.status === 'completed').length, preview: f.preview || null,
    ...(full ? { json: f.json } : {}),
  };
};

// Indeks token → pengiriman (dibangun saat pertama dipakai)
let wafTokenIdx = null;
const wafByToken = (token) => {
  if (!wafTokenIdx) { wafTokenIdx = new Map(); for (const s of db.flowSubmissions) wafTokenIdx.set(s.token, s); }
  return token ? wafTokenIdx.get(token) || null : null;
};
const wafSubmissions = (flowId) => db.flowSubmissions.filter((s) => s.flowId === String(flowId));
function pushSubmission(s) {
  wafByToken(null);
  db.flowSubmissions.push(s); wafTokenIdx.set(s.token, s);
  if (db.flowSubmissions.length > WAF_SUBMISSIONS_MAX) for (const old of db.flowSubmissions.splice(0, db.flowSubmissions.length - WAF_SUBMISSIONS_MAX)) wafTokenIdx.delete(old.token);
}
// Dipanggil dari addMessage untuk pesan keluar yang membawa flowToken
function recordFlowSend(conv, msg) {
  const c = msg.content;
  if (wafByToken(c.flowToken)) return;
  pushSubmission({ id: uid('fs_'), token: c.flowToken, flowId: c.flowId || null, flowName: c.flowName || 'Flow', conversationId: conv.id, contactId: conv.contactId,
    messageId: msg.id, via: msg.type === 'template' ? 'template' : msg.auto ? 'automation' : 'inbox', mode: c.mode || 'published',
    sentBy: msg.userName || '', sentAt: msg.timestamp, status: 'sent', response: null, completedAt: 0 });
}
function recordFlowSubmission(conv, contact, msg) {
  const c = msg.content;
  let s = wafByToken(c.token);
  if (!s) {
    // Token tidak dikenal (mis. flow dikirim di luar Kontaq): kaitkan ke flow dari pesan yang dibalas bila ada
    const orig = msg.contextId ? idx.wamid.get(msg.contextId) : null;
    s = { id: uid('fs_'), token: c.token || uid('tk_'), flowId: orig?.content?.flowId || null, flowName: orig?.content?.flowName || 'Flow tidak dikenal',
      conversationId: conv.id, contactId: contact.id, messageId: null, via: 'external', mode: 'published', sentBy: '', sentAt: 0, status: 'sent', response: null, completedAt: 0 };
    pushSubmission(s);
  }
  // Jawaban ganda untuk token yang sama: simpan jawaban terakhir
  Object.assign(s, { status: 'completed', response: c.response, completedAt: msg.timestamp, responseMessageId: msg.id });
  msg.content.flowName = s.flowName; msg.content.flowId = s.flowId;
  save();
  io?.to('admins').emit('waflow:submission', { flowId: s.flowId, id: s.id });
}

// Pesan interaktif "flow". b: { flowId, body, cta, header?, footer?, screen?, mode?, data? }
function buildWaFlowMessage(b) {
  const f = wafById(b.flowId);
  if (!f) throw new HttpError(400, 'WhatsApp Flow tidak ditemukan. Sinkronkan daftar flow terlebih dahulu.');
  const mode = b.mode === 'draft' ? 'draft' : 'published';
  if (['DEPRECATED', 'BLOCKED'].includes(f.status)) throw new HttpError(400, `Flow "${f.name}" berstatus ${f.status} dan tidak dapat dikirim.`);
  if (mode === 'published' && !['PUBLISHED', 'THROTTLED'].includes(f.status)) throw new HttpError(400, `Flow "${f.name}" belum diterbitkan (status ${f.status}). Terbitkan dulu, atau kirim dalam mode draft untuk uji.`);
  const body = str(b.body, 1024), cta = str(b.cta, 30);
  if (!body) throw new HttpError(400, 'Isi teks pesan.');
  if (!cta) throw new HttpError(400, 'Isi teks tombol (maks. 30 karakter).');
  const screen = str(b.screen, 80) || wafScreens(f.json)[0]?.id;
  if (!screen) throw new HttpError(400, 'Isi ID screen pertama (Flow JSON belum dimuat — buka flow di menu WhatsApp Flows).');
  const token = newFlowToken();
  const payload = { screen };
  if (b.data && typeof b.data === 'object' && !Array.isArray(b.data) && Object.keys(b.data).length) payload.data = b.data;
  const interactive = { type: 'flow', body: { text: body },
    action: { name: 'flow', parameters: { flow_message_version: '3', flow_token: token, flow_id: f.id, flow_cta: cta, mode, flow_action: 'navigate', flow_action_payload: payload } } };
  const header = str(b.header, 60), footer = str(b.footer, 60);
  if (header) interactive.header = { type: 'text', text: header };
  if (footer) interactive.footer = { text: footer };
  return { interactive, content: { kind: 'flow', header, body, footer, button: cta, flowId: f.id, flowName: f.name, flowToken: token, mode }, token };
}

function handleWaFlowWebhook(v) {
  const f = wafById(v.flow_id);
  if (!f) return;
  if (v.event === 'FLOW_STATUS_CHANGE' && v.new_status) f.status = v.new_status;
  f.alerts = [{ at: now(), event: v.event, message: v.message || '', state: v.alert_state || null, oldStatus: v.old_status || null, newStatus: v.new_status || null }, ...(f.alerts || [])].slice(0, 20);
  save();
  io?.to('admins').emit('waflow:update', wafPublic(f));
}

function handleTemplateStatus(value) {
  const t = db.templates.find((x) => String(x.id) === String(value.message_template_id) || (x.name === value.message_template_name && x.language === value.message_template_language));
  if (t) {
    t.status = value.event;
    if (value.reason && value.reason !== 'NONE') t.rejected_reason = value.reason;
    save();
  }
  io?.emit('template:update', { id: value.message_template_id, name: value.message_template_name, language: value.message_template_language, status: value.event, reason: value.reason });
}

function handleCalls(value) {
  for (const c of value.calls || []) {
    let call = db.calls.find((x) => x.callId === c.id);
    if (!call) {
      const phone = normPhone(c.direction === 'BUSINESS_INITIATED' ? c.to : c.from);
      const contact = getOrCreateContact(phone, (value.contacts || []).find((x) => x.wa_id === c.from)?.profile?.name);
      call = { id: uid('k_'), callId: c.id, contactId: contact.id, phone, direction: c.direction || 'USER_INITIATED', status: 'ringing', startedAt: Number(c.timestamp) * 1000 || now(), answeredBy: null };
      db.calls.push(call);
    }
    if (c.event === 'connect' && call.direction === 'BUSINESS_INITIATED') {
      // Pengguna mengangkat telepon balik: teruskan SDP answer hanya ke agen yang menelepon
      if (c.session?.sdp_type === 'answer' && c.session.sdp) {
        call.status = 'accepted'; call.answeredAt = now();
        if (call.callerId) io?.to('user:' + call.callerId).emit('call:answer', { id: call.id, sdp: c.session.sdp });
        io?.emit('call:update', publicCall(call));
      }
    } else if (c.event === 'connect') {
      if (c.session?.sdp) call.offer = c.session.sdp;
      if (call.status === 'ringing') {
        io?.emit('call:incoming', { ...publicCall(call), offer: call.offer });
        if (!call.notified) { call.notified = true; notifyIncomingCall(call); }
      }
    } else if (c.event === 'terminate') {
      call.status = (c.status || 'COMPLETED').toLowerCase();
      call.duration = c.duration || 0;
      call.endedAt = Number(c.end_time || c.timestamp) * 1000 || now();
      delete call.offer;
      io?.emit('call:update', publicCall(call));
    }
  }
  for (const s of value.statuses || []) {
    const call = db.calls.find((x) => x.callId === s.id);
    if (!call) continue;
    const st = String(s.status).toLowerCase();
    if (call.status === 'accepted' && st === 'ringing') continue;
    call.status = st; io?.emit('call:update', publicCall(call));
  }
  save();
}
function publicCall(c) {
  const contact = byId('contacts', c.contactId);
  const { offer, ...rest } = c;
  return { ...rest, contactName: contact?.name || contact?.waName || '', avatarV: contact?.avatarV || 0 };
}

/* ───────────────────────── 6b. Notifikasi WhatsApp via gateway ─────────────────────────
 * Kredensial gateway diatur admin; tiap pengguna mengaktifkan notifikasi ke nomor WA pribadinya
 * (Pengaturan › Notifikasi & keamanan). Terpisah dari Cloud API: dikirim lewat gateway pihak ketiga.
 */
const WA_NOTIFY_EVENTS = ['message', 'assign', 'call'];
const WA_NOTIFY_COOLDOWN_MS = 2 * 60 * 1000; // maks. 1 notifikasi pesan per percakapan per pengguna
const waNotifyLast = new Map(); // `${userId}:${convId}` -> waktu kirim terakhir

function waGateway() {
  const g = db.settings.waGateway || {};
  return {
    url: g.url || process.env.WA_GATEWAY_URL || 'https://notif.beliakun.id/api/send-message',
    device: g.device || process.env.WA_GATEWAY_DEVICE || '',
    apiKey: decrypt(g.apiKeyEnc) || process.env.WA_GATEWAY_API_KEY || '',
  };
}
const waNotifyOf = (u) => ({ enabled: false, phone: '', onlyOffline: true, ...u.waNotify, events: { message: true, assign: true, call: true, ...u.waNotify?.events } });

async function gatewaySend(to, message) {
  const g = waGateway();
  if (!g.apiKey || !g.device) throw new HttpError(400, 'Gateway WA belum dikonfigurasi admin (API key / device kosong).');
  try {
    const r = await axios({
      method: 'POST', url: g.url, timeout: 15000,
      headers: { 'x-api-key': g.apiKey, 'Content-Type': 'application/json' },
      data: { device: g.device, to, message },
    });
    if (r.data?.status === false || r.data?.success === false) throw new Error(r.data.message || r.data.msg || 'ditolak gateway');
    return r.data;
  } catch (e) {
    const detail = e.response?.data?.message || e.response?.data?.msg || e.message;
    throw new HttpError(502, `Gateway WA: ${detail}`);
  }
}

// Antrean berurutan agar gateway tidak dibanjiri saat banyak notifikasi bersamaan
let waNotifyChain = Promise.resolve();
function queueWaNotify(user, message) {
  const to = waNotifyOf(user).phone;
  waNotifyChain = waNotifyChain.then(() => gatewaySend(to, message)).catch((e) => console.warn('[wa-notify]', user.email, e.message));
}
const userOnline = (userId) => (io?.sockets.adapter.rooms.get('user:' + userId)?.size || 0) > 0;

function notifyUsers(event, users, message) {
  for (const u of users) {
    const n = waNotifyOf(u);
    if (!u.active || !n.enabled || !validPhone(n.phone) || !n.events[event]) continue;
    if (n.onlyOffline && userOnline(u.id)) continue;
    queueWaNotify(u, message);
  }
}
const appLink = (hash) => (process.env.PUBLIC_URL ? process.env.PUBLIC_URL.replace(/\/$/, '') + '/' + hash : '');
const contactLabel = (c) => `${c?.name || c?.waName || 'Pelanggan'} (+${c?.phone || '?'})`;

function notifyInboundMessage(conv, msg) {
  if (!waGateway().apiKey) return;
  const contact = byId('contacts', conv.contactId);
  const users = (conv.assignedTo ? [byId('users', conv.assignedTo)] : db.users).filter(Boolean).filter((u) => {
    const key = `${u.id}:${conv.id}`;
    if (now() - (waNotifyLast.get(key) || 0) < WA_NOTIFY_COOLDOWN_MS) return false;
    if (waNotifyOf(u).enabled) waNotifyLast.set(key, now());
    return true;
  });
  const text = String(previewOf(msg) || '').slice(0, 300);
  notifyUsers('message', users, `🔔 *Kontaq* — Pesan baru dari ${contactLabel(contact)}\n\n${text}${appLink('#/inbox/' + conv.id) ? '\n\n' + appLink('#/inbox/' + conv.id) : ''}`);
}
function notifyAssigned(conv, target, by) {
  if (!waGateway().apiKey) return;
  const contact = byId('contacts', conv.contactId);
  notifyUsers('assign', [target], `📌 *Kontaq* — ${by.name} menugaskan percakapan ${contactLabel(contact)} kepada Anda.${conv.preview ? `\n\nPesan terakhir: ${conv.preview}` : ''}${appLink('#/inbox/' + conv.id) ? '\n\n' + appLink('#/inbox/' + conv.id) : ''}`);
}
function notifyIncomingCall(call) {
  if (!waGateway().apiKey) return;
  const contact = byId('contacts', call.contactId);
  notifyUsers('call', db.users, `📞 *Kontaq* — Panggilan masuk dari ${contactLabel(contact)}. Buka Kontaq untuk menjawab.${appLink('#/calls') ? '\n\n' + appLink('#/calls') : ''}`);
}

/* ───────────────────────── 7. Express & Routes ───────────────────────── */

const app = express();
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
app.disable('x-powered-by');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(self), geolocation=(self), microphone=(self)',
  });
  next();
});
app.use(express.json({ limit: '2mb', verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use('/public', express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));
app.use((req, res, next) => { req.user = userFromToken(parseCookies(req.headers.cookie)[COOKIE_NAME]); next(); });

// CSRF: semua request API yang mengubah data wajib membawa header khusus (memicu preflight lintas origin).
app.use('/api', (req, res, next) => {
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.get('x-requested-with') !== 'kontaq') return next(new HttpError(403, 'Permintaan ditolak (CSRF).'));
  next();
});

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024 } });

// Batas ukuran & MIME sesuai dokumentasi Cloud API
const MEDIA_RULES = {
  image: { max: 5, mimes: ['image/jpeg', 'image/png'] },
  video: { max: 16, mimes: ['video/mp4', 'video/3gpp'] },
  audio: { max: 16, mimes: ['audio/aac', 'audio/amr', 'audio/mpeg', 'audio/mp4', 'audio/ogg'] },
  document: { max: 100, mimes: null },
  sticker: { max: 0.5, mimes: ['image/webp'] },
  // Rekaman voice note dari browser: dikonversi ke OGG/Opus (format wajib pesan suara WhatsApp)
  voice: { max: 16, mimes: ['audio/webm', 'video/webm', 'audio/ogg', 'audio/mp4', 'audio/x-m4a', 'audio/aac'] },
};
// Browser kadang mengirim dokumen sebagai application/octet-stream: tentukan MIME dari ekstensi
const DOC_MIMES = { pdf: 'application/pdf', txt: 'text/plain', csv: 'text/csv', doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', zip: 'application/zip' };

/* ── Voice note: WebM/Opus (Chrome/Edge) → OGG/Opus ──
 * Remux tanpa encode ulang: paket Opus dari blok WebM dipindahkan ke halaman Ogg (RFC 7845). Firefox sudah merekam OGG.
 */
const OGG_CRC = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) { let r = i << 24; for (let j = 0; j < 8; j++) r = r & 0x80000000 ? ((r << 1) ^ 0x04c11db7) >>> 0 : (r << 1) >>> 0; t[i] = r; }
  return t;
})();
function oggCrc(buf) { let c = 0; for (let i = 0; i < buf.length; i++) c = ((c << 8) ^ OGG_CRC[((c >>> 24) ^ buf[i]) & 0xff]) >>> 0; return c; }
function oggPage(packets, granule, serial, seq, flags) {
  const segs = [];
  for (const p of packets) { let n = p.length; while (n >= 255) { segs.push(255); n -= 255; } segs.push(n); }
  const head = Buffer.alloc(27 + segs.length);
  head.write('OggS', 0); head[4] = 0; head[5] = flags;
  head.writeBigInt64LE(BigInt(granule), 6); head.writeUInt32LE(serial, 14); head.writeUInt32LE(seq, 18);
  head[26] = segs.length; segs.forEach((s, i) => { head[27 + i] = s; });
  const page = Buffer.concat([head, ...packets]);
  page.writeUInt32LE(oggCrc(page), 22);
  return page;
}
// Jumlah sampel (48 kHz) dalam satu paket Opus, dari byte TOC (RFC 6716 §3.1)
function opusSamples(p) {
  if (!p.length) return 0;
  const cfg = p[0] >> 3, code = p[0] & 3;
  const ms = cfg < 12 ? [10, 20, 40, 60][cfg & 3] : cfg < 16 ? [10, 20][cfg & 1] : [2.5, 5, 10, 20][cfg & 3];
  const frames = code === 0 ? 1 : code === 3 ? (p[1] || 0) & 0x3f : 2;
  return Math.round(frames * ms * 48);
}
// Ambil paket Opus dari WebM (EBML). Segment/Cluster dengan ukuran "unknown" (MediaRecorder) ditangani dengan menelusuri isinya.
function webmOpusPackets(buf) {
  const MASTER = new Set([0x18538067, 0x1f43b675, 0x1654ae6b, 0xae, 0xa0, 0xe1]); // Segment, Cluster, Tracks, TrackEntry, BlockGroup, Audio
  let pos = 0, curTrack = 0, opusTrack = null, head = null, channels = 1;
  const packets = [];
  const vint = (keep) => {
    const b = buf[pos]; let len = 1, mask = 0x80;
    while (len <= 8 && !(b & mask)) { len++; mask >>= 1; }
    if (len > 8 || pos + len > buf.length) throw new Error('rekaman rusak');
    let v = keep ? b : b & (mask - 1), ones = (b & (mask - 1)) === mask - 1;
    for (let i = 1; i < len; i++) { v = v * 256 + buf[pos + i]; if (buf[pos + i] !== 0xff) ones = false; }
    pos += len;
    return { v, unknown: !keep && ones };
  };
  const uint = (d) => d.reduce((n, x) => n * 256 + x, 0);
  while (pos < buf.length) {
    const id = vint(true).v, size = vint(false);
    if (MASTER.has(id)) continue; // telusuri anak elemen
    const end = size.unknown ? buf.length : Math.min(buf.length, pos + size.v), d = buf.subarray(pos, end);
    if (id === 0xd7) curTrack = uint(d);
    else if (id === 0x86 && d.toString('latin1') === 'A_OPUS' && opusTrack == null) opusTrack = curTrack;
    else if (id === 0x63a2 && d.subarray(0, 8).toString('latin1') === 'OpusHead') head = Buffer.from(d);
    else if (id === 0x9f) channels = uint(d);
    else if ((id === 0xa3 || id === 0xa1) && d.length > 4) { // SimpleBlock / Block
      let p = 0, len = 1, mask = 0x80;
      while (len <= 8 && !(d[0] & mask)) { len++; mask >>= 1; }
      let track = d[0] & (mask - 1);
      for (let i = 1; i < len; i++) track = track * 256 + d[i];
      p = len + 3; // nomor track + timecode (2) + flags (1)
      const lacing = (d[len + 2] >> 1) & 3;
      if (opusTrack == null || track === opusTrack) {
        if (lacing === 0) packets.push(Buffer.from(d.subarray(p)));
        else if (lacing === 2) { const n = d[p] + 1, data = d.subarray(p + 1), sz = data.length / n; for (let i = 0; i < n; i++) packets.push(Buffer.from(data.subarray(i * sz, (i + 1) * sz))); }
        else throw new Error('format lacing rekaman tidak didukung');
      }
    }
    pos = end;
  }
  return { packets, head, channels };
}
function webmToOgg(buf) {
  const { packets, head: rawHead, channels } = webmOpusPackets(buf);
  if (!packets.length) throw new HttpError(400, 'Rekaman kosong atau bukan audio Opus.');
  let head = rawHead;
  if (!head) { // OpusHead minimal bila CodecPrivate tidak ada
    head = Buffer.alloc(19); head.write('OpusHead', 0); head[8] = 1; head[9] = channels; head.writeUInt16LE(312, 10); head.writeUInt32LE(48000, 12);
  }
  const vendor = Buffer.from('Kontaq'), tags = Buffer.alloc(8 + 4 + vendor.length + 4);
  tags.write('OpusTags', 0); tags.writeUInt32LE(vendor.length, 8); vendor.copy(tags, 12);
  const serial = crypto.randomBytes(4).readUInt32LE(0);
  const pages = [oggPage([head], 0, serial, 0, 2), oggPage([tags], 0, serial, 1, 0)];
  let granule = 0, seq = 2;
  for (let i = 0; i < packets.length; i += 50) {
    const group = packets.slice(i, i + 50);
    granule += group.reduce((t, p) => t + opusSamples(p), 0);
    pages.push(oggPage(group, granule, serial, seq++, i + 50 >= packets.length ? 4 : 0));
  }
  return { buffer: Buffer.concat(pages), channels: head[9], duration: Math.max(0, (granule - head.readUInt16LE(10)) / 48000) };
}
// Info OGG/Opus asli (Firefox): jumlah kanal & durasi dari granule halaman terakhir
function oggOpusInfo(buf) {
  const h = buf.indexOf('OpusHead');
  if (buf.subarray(0, 4).toString() !== 'OggS' || h < 0) return null;
  const last = buf.lastIndexOf('OggS');
  const granule = Number(buf.readBigInt64LE(last + 6));
  return { channels: buf[h + 9], duration: Math.max(0, (granule - buf.readUInt16LE(h + 10)) / 48000) };
}
// Ukuran & animasi WebP (VP8 / VP8L / VP8X)
function webpInfo(buf) {
  if (buf.length < 30 || buf.toString('latin1', 0, 4) !== 'RIFF' || buf.toString('latin1', 8, 12) !== 'WEBP') return null;
  const chunk = buf.toString('latin1', 12, 16);
  if (chunk === 'VP8X') return { width: 1 + buf.readUIntLE(24, 3), height: 1 + buf.readUIntLE(27, 3), animated: !!(buf[20] & 0x02) };
  if (chunk === 'VP8 ') return { width: buf.readUInt16LE(26) & 0x3fff, height: buf.readUInt16LE(28) & 0x3fff, animated: false };
  if (chunk === 'VP8L') { const b = buf.readUInt32LE(21); return { width: (b & 0x3fff) + 1, height: ((b >> 14) & 0x3fff) + 1, animated: false }; }
  return null;
}
function checkSticker(buf) {
  const info = webpInfo(buf);
  if (!info) throw new HttpError(400, 'Stiker harus berformat WebP.');
  if (info.width !== 512 || info.height !== 512) throw new HttpError(400, `Stiker harus 512×512 piksel (file ini ${info.width}×${info.height}).`);
  if (buf.length > (info.animated ? 500 : 100) * 1024) throw new HttpError(400, `Stiker ${info.animated ? 'animasi maks. 500' : 'statis maks. 100'} KB (file ini ${Math.ceil(buf.length / 1024)} KB).`);
  return info;
}

/* Cache media lokal: media keluar disimpan saat diunggah, media masuk saat pertama dibuka.
 * Mempercepat tampilan & mendukung Range (seek audio/video). Berkas > 30 hari dibersihkan otomatis. */
const MEDIA_CACHE_DIR = path.join(DATA_DIR, 'media-cache');
const MEDIA_CACHE_MAX = 2 * 1024 * 1024 * 1024;
if (!fs.existsSync(MEDIA_CACHE_DIR)) fs.mkdirSync(MEDIA_CACHE_DIR, { recursive: true });
const mediaCacheFile = (id) => path.join(MEDIA_CACHE_DIR, String(id).replace(/\D/g, ''));
function cacheMedia(id, buffer, meta) {
  try { fs.writeFileSync(mediaCacheFile(id), buffer); fs.writeFileSync(mediaCacheFile(id) + '.json', JSON.stringify(meta)); }
  catch (e) { console.warn('[media-cache]', e.message); }
}
function cachedMedia(id) {
  try { const f = mediaCacheFile(id); return fs.existsSync(f) ? { file: f, ...JSON.parse(fs.readFileSync(f + '.json', 'utf8')) } : null; } catch { return null; }
}
setInterval(() => {
  try {
    const files = fs.readdirSync(MEDIA_CACHE_DIR).filter((f) => !f.endsWith('.json') && !f.endsWith('.tmp')).map((f) => { const p = path.join(MEDIA_CACHE_DIR, f); const s = fs.statSync(p); return { p, at: s.mtimeMs, size: s.size }; }).sort((a, b) => a.at - b.at);
    let total = files.reduce((t, f) => t + f.size, 0);
    for (const f of files) {
      if (now() - f.at < 30 * 86400000 && total <= MEDIA_CACHE_MAX) break;
      fs.rmSync(f.p, { force: true }); fs.rmSync(f.p + '.json', { force: true }); total -= f.size;
    }
  } catch (e) { console.warn('[media-cache]', e.message); }
}, 3600000);

/* Pustaka stiker bersama (berkas di data/stickers, metadata di db.stickers). Media ID Meta diunggah ulang setelah 25 hari. */
const STICKER_DIR = path.join(DATA_DIR, 'stickers');
const STICKERS_MAX = 120;
if (!fs.existsSync(STICKER_DIR)) fs.mkdirSync(STICKER_DIR, { recursive: true });
const stickerFile = (id) => path.join(STICKER_DIR, String(id).replace(/[^\w-]/g, '') + '.webp');
const stickerOr404 = (id) => { const s = (db.stickers || []).find((x) => x.id === String(id)); if (!s) throw new HttpError(404, 'Stiker tidak ditemukan.'); return s; };
function addSticker(buf, by) {
  const info = checkSticker(buf);
  const hash = crypto.createHash('sha256').update(buf).digest('hex').slice(0, 16);
  db.stickers = db.stickers || [];
  let s = db.stickers.find((x) => x.hash === hash);
  if (!s) {
    s = { id: uid('st_').replace(/[^\w-]/g, ''), hash, animated: info.animated, size: buf.length, createdAt: now(), lastUsedAt: now(), createdBy: by, metaId: null, metaAt: 0 };
    fs.writeFileSync(stickerFile(s.id), buf);
    db.stickers.push(s);
    // Pustaka penuh: buang yang paling lama tidak dipakai
    while (db.stickers.length > STICKERS_MAX) { const old = db.stickers.sort((a, b) => a.lastUsedAt - b.lastUsedAt).shift(); fs.rmSync(stickerFile(old.id), { force: true }); }
  }
  s.lastUsedAt = now(); save();
  return s;
}
async function ensureStickerMedia(s) {
  if (s.metaId && now() - s.metaAt < 25 * 86400000) return s.metaId;
  const buffer = fs.readFileSync(stickerFile(s.id));
  s.metaId = await uploadMedia({ buffer, mimetype: 'image/webp', originalname: s.id + '.webp' }); s.metaAt = now(); save();
  cacheMedia(s.metaId, buffer, { mime: 'image/webp', size: buffer.length, filename: s.id + '.webp' });
  return s.metaId;
}

/* Halaman */
app.get('/', (req, res) => {
  res.render('index', {
    user: publicUser(req.user), needsSetup: db.users.length === 0,
    // Versi aset dari waktu ubah file: browser HP langsung memuat CSS terbaru setelah update
    assetVersion: Math.floor(fs.statSync(path.join(__dirname, 'public', 'style.css')).mtimeMs).toString(36),
    boot: req.user ? { user: publicUser(req.user), campaignRate: CAMPAIGN_RATE } : null,
  });
});

/* Webhook Meta */
app.get('/webhook', (req, res) => {
  const vt = meta().verifyToken;
  if (req.query['hub.mode'] === 'subscribe' && vt && req.query['hub.verify_token'] === vt) return res.status(200).send(String(req.query['hub.challenge']));
  res.sendStatus(403);
});
app.post('/webhook', (req, res) => {
  const sigError = verifySignature(req);
  if (sigError) { console.warn(`[webhook] ditolak: ${sigError}`); return res.sendStatus(401); }
  res.sendStatus(200); // balas cepat; proses setelahnya
  try {
    db.settings.lastWebhookAt = now();
    for (const entry of req.body?.entry || []) {
      for (const change of entry.changes || []) {
        const v = change.value || {};
        if (change.field === 'messages') {
          const ourPhone = meta().phoneNumberId;
          if (ourPhone && v.metadata?.phone_number_id && v.metadata.phone_number_id !== ourPhone) continue;
          handleMessages(v); handleStatuses(v);
        } else if (change.field === 'message_template_status_update') handleTemplateStatus(v);
        else if (change.field === 'calls') handleCalls(v);
        else if (change.field === 'flows') handleWaFlowWebhook(v);
        else if (GROUP_FIELDS.includes(change.field)) {
          const ourPhone = meta().phoneNumberId;
          if (ourPhone && v.metadata?.phone_number_id && v.metadata.phone_number_id !== ourPhone) continue;
          handleGroupWebhook(change.field, v);
        }
      }
    }
    save();
  } catch (e) { console.error('[webhook] gagal diproses', e); }
});

/* Auth */
app.post('/api/setup', wrap(async (req, res) => {
  if (db.users.length) throw new HttpError(400, 'Setup sudah dilakukan.');
  const name = str(req.body.name, 80), email = str(req.body.email, 120).toLowerCase();
  if (!name || !/^\S+@\S+\.\S+$/.test(email)) throw new HttpError(400, 'Nama dan email valid wajib diisi.');
  validatePassword(req.body.password);
  const user = { id: uid('u_'), name, email, role: 'admin', active: true, createdAt: now(), sessionVersion: 0, ...hashPassword(req.body.password) };
  db.users.push(user); save();
  req.user = user; audit(req, 'setup', 'Admin pertama dibuat');
  setSessionCookie(res, makeToken(user));
  res.json({ user: publicUser(user) });
}));
app.post('/api/login', wrap(async (req, res) => {
  loginGuard(req.ip);
  const email = str(req.body.email, 120).toLowerCase();
  const user = db.users.find((u) => u.email === email);
  if (!user || !user.active || !checkPassword(user, req.body.password || '')) {
    loginFail(req.ip);
    audit(req, 'login.failed', email);
    throw new HttpError(401, 'Email atau kata sandi salah.');
  }
  loginAttempts.delete(req.ip);
  user.lastLoginAt = now(); req.user = user; audit(req, 'login', '');
  setSessionCookie(res, makeToken(user));
  res.json({ user: publicUser(user) });
}));
app.post('/api/logout', (req, res) => {
  if (req.user) audit(req, 'logout', '');
  setSessionCookie(res, '', 0);
  res.json({ ok: true });
});

app.use('/api', requireAuth);

app.get('/api/me', (req, res) => res.json({ user: publicUser(req.user) }));
app.post('/api/me/password', wrap(async (req, res) => {
  if (!checkPassword(req.user, req.body.current || '')) throw new HttpError(400, 'Kata sandi saat ini salah.');
  validatePassword(req.body.password);
  Object.assign(req.user, hashPassword(req.body.password));
  req.user.sessionVersion = (req.user.sessionVersion || 0) + 1; // keluarkan sesi lain
  audit(req, 'password.change', ''); save();
  setSessionCookie(res, makeToken(req.user));
  res.json({ ok: true });
}));
app.post('/api/me/logout-all', (req, res) => {
  req.user.sessionVersion = (req.user.sessionVersion || 0) + 1;
  audit(req, 'session.revoke_all', ''); save();
  setSessionCookie(res, makeToken(req.user));
  res.json({ ok: true });
});

/* Notifikasi WhatsApp milik pengguna (via gateway) */
app.get('/api/me/wa-notify', (req, res) => {
  const g = waGateway();
  res.json({ ...waNotifyOf(req.user), gatewayReady: !!(g.apiKey && g.device) });
});
app.put('/api/me/wa-notify', wrap(async (req, res) => {
  const b = req.body, n = waNotifyOf(req.user);
  if (b.phone !== undefined) {
    let p = normPhone(b.phone); if (p.startsWith('0')) p = '62' + p.slice(1);
    if (p && !validPhone(p)) throw new HttpError(400, 'Nomor WhatsApp tidak valid (contoh: 6281234567890).');
    n.phone = p;
  }
  if (typeof b.enabled === 'boolean') n.enabled = b.enabled;
  if (typeof b.onlyOffline === 'boolean') n.onlyOffline = b.onlyOffline;
  for (const k of WA_NOTIFY_EVENTS) if (typeof b.events?.[k] === 'boolean') n.events[k] = b.events[k];
  if (n.enabled && !n.phone) throw new HttpError(400, 'Isi nomor WhatsApp terlebih dahulu.');
  req.user.waNotify = n;
  audit(req, 'wa_notify.update', `${n.enabled ? 'aktif' : 'nonaktif'} ${n.phone ? '+' + n.phone : ''}`); save();
  res.json(n);
}));
app.post('/api/me/wa-notify/test', wrap(async (req, res) => {
  const n = waNotifyOf(req.user);
  if (!validPhone(n.phone)) throw new HttpError(400, 'Simpan nomor WhatsApp terlebih dahulu.');
  await gatewaySend(n.phone, `✅ *Kontaq* — Tes notifikasi untuk ${req.user.name}. Notifikasi WhatsApp berfungsi.`);
  res.json({ ok: true });
}));

/* Gateway notifikasi WA (admin) */
app.get('/api/settings/wa-gateway', requireAdmin, (req, res) => {
  const g = waGateway();
  res.json({ url: g.url, device: g.device, apiKeyMasked: mask(g.apiKey), users: db.users.filter((u) => waNotifyOf(u).enabled).length });
});
app.put('/api/settings/wa-gateway', requireAdmin, wrap(async (req, res) => {
  const b = req.body, g = (db.settings.waGateway ||= {});
  if (b.url !== undefined) {
    const url = str(b.url, 500);
    if (url && !/^https?:\/\/\S+$/.test(url)) throw new HttpError(400, 'URL gateway tidak valid.');
    g.url = url;
  }
  if (b.device !== undefined) g.device = str(b.device, 100);
  if (b.apiKey) g.apiKeyEnc = encrypt(str(b.apiKey, 500));
  if (b.clearApiKey === true) delete g.apiKeyEnc;
  audit(req, 'settings.wa_gateway', `Diperbarui: ${Object.keys(b).filter((k) => b[k] !== undefined && b[k] !== '').join(', ')}`); save();
  res.json({ ok: true });
}));
app.post('/api/settings/wa-gateway/test', requireAdmin, wrap(async (req, res) => {
  let to = normPhone(req.body.to); if (to.startsWith('0')) to = '62' + to.slice(1);
  if (!validPhone(to)) throw new HttpError(400, 'Nomor tujuan tidak valid.');
  const r = await gatewaySend(to, '✅ *Kontaq* — Tes koneksi gateway notifikasi WhatsApp berhasil.');
  audit(req, 'settings.wa_gateway.test', '+' + to);
  res.json({ ok: true, response: r });
}));

/* Pengaturan Meta (admin) */
app.get('/api/settings/meta', requireAdmin, (req, res) => {
  const m = meta();
  res.json({
    graphVersion: m.graphVersion, phoneNumberId: m.phoneNumberId, wabaId: m.wabaId, verifyToken: m.verifyToken,
    accessTokenMasked: mask(m.accessToken), appSecretMasked: mask(m.appSecret),
    webhookUrl: (process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '') + '/webhook',
    lastWebhookAt: db.settings.lastWebhookAt || 0, connection: db.settings.connection || null,
  });
});
app.put('/api/settings/meta', requireAdmin, wrap(async (req, res) => {
  const b = req.body, s = db.settings;
  if (b.graphVersion !== undefined) {
    if (!/^v\d{2}\.\d$/.test(b.graphVersion)) throw new HttpError(400, 'Versi Graph API tidak valid (contoh: v23.0).');
    s.graphVersion = b.graphVersion;
  }
  for (const k of ['phoneNumberId', 'wabaId']) {
    if (b[k] !== undefined) {
      if (b[k] && !/^\d{5,25}$/.test(b[k])) throw new HttpError(400, `${k} harus berupa angka.`);
      s[k] = b[k];
    }
  }
  if (b.verifyToken !== undefined) s.verifyToken = str(b.verifyToken, 200);
  if (b.accessToken) s.accessTokenEnc = encrypt(str(b.accessToken, 2000));
  if (b.appSecret) s.appSecretEnc = encrypt(str(b.appSecret, 200));
  s.connection = null;
  audit(req, 'settings.meta', `Diperbarui: ${Object.keys(b).filter((k) => b[k] !== undefined && b[k] !== '').join(', ')}`);
  save();
  res.json({ ok: true });
}));
app.post('/api/settings/meta/test', requireAdmin, wrap(async (req, res) => {
  const phone = await graph('get', needPhone(), { params: { fields: 'display_phone_number,verified_name,quality_rating,code_verification_status,platform_type,throughput,name_status' } });
  const waba = await graph('get', needWaba(), { params: { fields: 'name,currency,timezone_id,message_template_namespace' } });
  let subscribed = null;
  try { subscribed = (await graph('get', `${needWaba()}/subscribed_apps`)).data || []; } catch { /* izin mungkin terbatas */ }
  db.settings.connection = { ok: true, checkedAt: now(), phone, waba, subscribedApps: subscribed?.map((a) => a.whatsapp_business_api_data?.name || a.name || a.id) || null };
  audit(req, 'settings.meta.test', 'Berhasil'); save();
  res.json(db.settings.connection);
}));
app.post('/api/settings/meta/subscribe', requireAdmin, wrap(async (req, res) => {
  const r = await graph('post', `${needWaba()}/subscribed_apps`);
  audit(req, 'settings.meta.subscribe', JSON.stringify(r));
  res.json(r);
}));

/* Pengguna / tim CS (admin) */
app.get('/api/users', (req, res) => {
  // Agen perlu daftar nama untuk penugasan; detail lengkap hanya untuk admin
  res.json(db.users.map((u) => (req.user.role === 'admin' ? publicUser(u) : { id: u.id, name: u.name, role: u.role, active: u.active })));
});
app.post('/api/users', requireAdmin, wrap(async (req, res) => {
  const name = str(req.body.name, 80), email = str(req.body.email, 120).toLowerCase();
  const role = req.body.role === 'admin' ? 'admin' : 'agent';
  if (!name || !/^\S+@\S+\.\S+$/.test(email)) throw new HttpError(400, 'Nama dan email valid wajib diisi.');
  if (db.users.some((u) => u.email === email)) throw new HttpError(400, 'Email sudah terdaftar.');
  validatePassword(req.body.password);
  const user = { id: uid('u_'), name, email, role, active: true, createdAt: now(), sessionVersion: 0, ...hashPassword(req.body.password) };
  db.users.push(user); audit(req, 'user.create', `${email} (${role})`); save();
  res.json(publicUser(user));
}));
app.patch('/api/users/:id', requireAdmin, wrap(async (req, res) => {
  const u = byId('users', req.params.id);
  if (!u) throw new HttpError(404, 'Pengguna tidak ditemukan.');
  const b = req.body;
  if (u.id === req.user.id && (b.role === 'agent' || b.active === false)) throw new HttpError(400, 'Tidak dapat menurunkan/menonaktifkan akun sendiri.');
  if (b.name) u.name = str(b.name, 80);
  if (b.role) u.role = b.role === 'admin' ? 'admin' : 'agent';
  if (typeof b.active === 'boolean') { u.active = b.active; if (!b.active) u.sessionVersion = (u.sessionVersion || 0) + 1; }
  if (b.password) { validatePassword(b.password); Object.assign(u, hashPassword(b.password)); u.sessionVersion = (u.sessionVersion || 0) + 1; }
  if (!u.active) db.conversations.forEach((c) => { if (c.assignedTo === u.id) c.assignedTo = null; });
  audit(req, 'user.update', `${u.email}: ${Object.keys(b).join(', ')}`); save();
  res.json(publicUser(u));
}));

/* Audit log (admin) */
/* Auto reply (admin) */
app.get('/api/autoreply', requireAdmin, (req, res) => {
  const cfg = arCfg();
  const z = zonedNow(cfg.timezone);
  res.json({ ...cfg, now: { day: z.day, time: z.time, open: isOpenNow(cfg) } });
});
app.put('/api/autoreply', requireAdmin, wrap(async (req, res) => {
  db.autoReply = validateAutoReply(req.body || {});
  const used = new Set([db.autoReply.welcome.image, db.autoReply.away.image, ...db.autoReply.rules.map((x) => x.image)].filter(Boolean));
  for (const k of Object.keys(db.arMedia)) if (!used.has(k) && !flowUsesImage(k) && now() - (db.arMedia[k].createdAt || 0) > 3600000) delete db.arMedia[k];
  audit(req, 'autoreply.update', `${db.autoReply.enabled ? 'aktif' : 'nonaktif'}, ${db.autoReply.rules.length} aturan kata kunci`); save();
  const z = zonedNow(db.autoReply.timezone);
  res.json({ ...db.autoReply, now: { day: z.day, time: z.time, open: isOpenNow(db.autoReply) } });
}));
// Simulasi: aturan mana yang akan membalas pesan ini sekarang (tidak mengirim apa pun)
app.post('/api/autoreply/test', requireAdmin, wrap(async (req, res) => {
  const cfg = req.body.config ? validateAutoReply(req.body.config) : arCfg();
  const d = decideAutoReply({ ...cfg, enabled: true }, { text: str(req.body.text, 1000), prevInboundAt: req.body.newContact ? 0 : now() - 3600000 });
  res.json({ label: d.label || null, kind: d.kind || null, matched: !!d.key, reply: d.key ? fillVars(d.reply || '', { name: 'Budi', phone: '6281234567890' }) : null, image: d.src?.image || null, buttons: d.src?.buttons || [], skip: d.skip || null });
}));
app.post('/api/autoreply/media', requireAdmin, wrap(async (req, res) => {
  const m = /^data:(image\/(?:jpeg|png));base64,([A-Za-z0-9+/=]+)$/.exec(String(req.body.dataUrl || ''));
  if (!m) throw new HttpError(400, 'Format gambar harus JPEG atau PNG.');
  if (m[2].length > 1.4 * 1024 * 1024) throw new HttpError(400, 'Gambar terlalu besar (maks. ~1 MB setelah dikompres).');
  const key = uid('am_');
  db.arMedia[key] = { mime: m[1], data: m[2], createdAt: now(), metaId: null, metaAt: 0 };
  audit(req, 'autoreply.media', key); save();
  res.json({ key });
}));
app.get('/api/autoreply/media/:key', (req, res) => {
  const m = db.arMedia[req.params.key];
  if (!m) return res.sendStatus(404);
  res.set('Cache-Control', 'private, max-age=86400').type(m.mime).send(Buffer.from(m.data, 'base64'));
});

/* Flow otomatis (admin) */
const flowSummary = (f) => ({
  id: f.id, name: f.name, enabled: f.enabled, order: f.order, settings: f.settings, stats: f.stats, updatedAt: f.updatedAt,
  steps: Object.keys(f.nodes).length - 1, conditions: Object.values(f.nodes).filter((n) => n.type === 'condition').length,
  waiting: db.flowRuns.filter((r) => r.flowId === f.id && FLOW_ACTIVE_RUN.includes(r.status)).length,
});
const flowOr404 = (id) => { const f = byId('flows', id); if (!f) throw new HttpError(404, 'Flow tidak ditemukan.'); return f; };
// Variabel run (mis. respons API & jawaban pelanggan yang masih menunggu) tidak dikirim ke browser
const recentRuns = (pred, n) => db.flowRuns.filter(pred).slice(-n).reverse().map(({ vars, input, ...r }) => ({ ...r, ...(input ? { input: { expiresAt: input.expiresAt, nodeId: input.nodeId } } : {}) }));
app.get('/api/flows', requireAdmin, (req, res) => {
  const z = zonedNow(flowTz());
  res.json({
    flows: db.flows.slice().sort((a, b) => a.order - b.order).map(flowSummary),
    runs: recentRuns(() => true, 30), timezone: flowTz(), now: z, labels: contactLabels(),
    autoReplyEnabled: !!arCfg().enabled, hours: arCfg().away.hours,
    waFlows: db.waFlows.map((f) => ({ id: f.id, name: f.name, status: f.status, screens: wafScreens(f.json) })),
  });
});
app.put('/api/flows/order', requireAdmin, wrap(async (req, res) => {
  const ids = Array.isArray(req.body.ids) ? req.body.ids.map(String) : [];
  ids.forEach((id, i) => { const f = byId('flows', id); if (f) f.order = i + 1; });
  audit(req, 'flow.order', ids.length + ' flow'); save();
  res.json({ ok: true });
}));
app.post('/api/flows/test', requireAdmin, wrap(async (req, res) => {
  const flow = validateFlow(req.body.flow || {}, req.body.flow?.id ? byId('flows', req.body.flow.id) : null);
  res.json(await testFlow(flow, req.body));
}));
app.get('/api/flows/runs', requireAdmin, (req, res) => {
  const flowId = str(req.query.flowId, 40);
  res.json(recentRuns((r) => !flowId || r.flowId === flowId, 100));
});
// Kredensial untuk langkah API Request ({{secret.NAMA}}): nilai disimpan terenkripsi dan tidak pernah dikembalikan ke browser
app.get('/api/flows/secrets', requireAdmin, (req, res) => {
  res.json(flowSecretNames().map((name) => ({ name, masked: mask(decrypt(db.settings.flowSecrets[name])), updatedAt: db.settings.flowSecretsAt?.[name] || 0 })));
});
app.put('/api/flows/secrets/:name', requireAdmin, wrap(async (req, res) => {
  const name = String(req.params.name || '');
  if (!/^[A-Z0-9_]{1,40}$/.test(name)) throw new HttpError(400, 'Nama kredensial hanya huruf besar, angka, dan garis bawah (mis. API_KEY).');
  const value = typeof req.body.value === 'string' ? req.body.value.trim() : '';
  if (!value || value.length > 2000) throw new HttpError(400, 'Isi nilai kredensial (maks. 2000 karakter).');
  db.settings.flowSecrets = { ...db.settings.flowSecrets, [name]: encrypt(value) };
  db.settings.flowSecretsAt = { ...db.settings.flowSecretsAt, [name]: now() };
  audit(req, 'flow.secret.set', name); save();
  res.json({ name, masked: mask(value), updatedAt: now() });
}));
app.delete('/api/flows/secrets/:name', requireAdmin, wrap(async (req, res) => {
  const name = String(req.params.name || '');
  const used = db.flows.filter((f) => JSON.stringify(f.nodes).includes(`secret.${name}`)).map((f) => f.name);
  if (used.length) throw new HttpError(400, `Kredensial masih dipakai flow: ${used.join(', ')}.`);
  if (db.settings.flowSecrets) delete db.settings.flowSecrets[name];
  audit(req, 'flow.secret.delete', name); save();
  res.json({ ok: true });
}));
app.post('/api/flows/runs/:id/cancel', requireAdmin, wrap(async (req, res) => {
  const n = cancelFlowRuns((r) => r.id === req.params.id, `Dibatalkan oleh ${req.user.name}.`);
  if (!n) throw new HttpError(400, 'Run tidak sedang menunggu.');
  audit(req, 'flow.run.cancel', req.params.id);
  res.json({ ok: true });
}));
app.get('/api/flows/:id', requireAdmin, (req, res) => {
  const f = flowOr404(req.params.id);
  res.json({ ...f, runs: recentRuns((r) => r.flowId === f.id, 30) });
});
app.post('/api/flows', requireAdmin, wrap(async (req, res) => {
  const f = validateFlow(req.body || {}, null);
  db.flows.push(f); audit(req, 'flow.create', `${f.name} (${f.enabled ? 'aktif' : 'nonaktif'})`); save();
  res.json({ ...f, runs: [] });
}));
app.put('/api/flows/:id', requireAdmin, wrap(async (req, res) => {
  const prev = flowOr404(req.params.id);
  const f = validateFlow(req.body || {}, prev);
  db.flows[db.flows.indexOf(prev)] = f;
  // Run yang menunggu di langkah yang sudah dihapus tidak dapat dilanjutkan
  cancelFlowRuns((r) => r.flowId === f.id && ((r.resumeNode && !f.nodes[r.resumeNode]) || (r.input && f.nodes[r.input.nodeId]?.type !== (r.input.kind === 'flow' ? 'waflow' : 'ask'))), 'Langkah dihapus saat flow diubah.');
  audit(req, 'flow.update', `${f.name} (${f.enabled ? 'aktif' : 'nonaktif'}, ${Object.keys(f.nodes).length - 1} langkah)`); save();
  res.json({ ...f, runs: recentRuns((r) => r.flowId === f.id, 30) });
}));
app.patch('/api/flows/:id', requireAdmin, wrap(async (req, res) => {
  const f = flowOr404(req.params.id);
  if (typeof req.body.enabled !== 'boolean') throw new HttpError(400, 'Nilai enabled tidak valid.');
  f.enabled = req.body.enabled; f.updatedAt = now();
  if (!f.enabled) cancelFlowRuns((r) => r.flowId === f.id, 'Flow dinonaktifkan.');
  audit(req, 'flow.toggle', `${f.name}: ${f.enabled ? 'aktif' : 'nonaktif'}`); save();
  res.json(flowSummary(f));
}));
app.delete('/api/flows/:id', requireAdmin, wrap(async (req, res) => {
  const f = flowOr404(req.params.id);
  cancelFlowRuns((r) => r.flowId === f.id, 'Flow dihapus.');
  db.flows.splice(db.flows.indexOf(f), 1);
  audit(req, 'flow.delete', f.name); save();
  res.json({ ok: true });
}));

/* Grup WhatsApp (admin) */
const groupMsgs = (g, n = 300) => db.messages.filter((m) => m.groupId === g.id).slice(-n);
const groupDetail = (g) => ({ ...groupSummary(g), events: g.events.slice(0, 100), invites: g.invites.slice(-100).reverse(), messages: groupMsgs(g) });
const needActiveGroup = (g) => { if (!g.groupId || ['creating', 'deleted', 'failed'].includes(g.status)) throw new HttpError(400, 'Grup belum aktif atau sudah dihapus.'); return g.groupId; };
app.get('/api/groups', requireAdmin, (req, res) => {
  res.json({
    groups: db.groups.slice().sort((a, b) => (b.lastMessageAt || b.createdAt) - (a.lastMessageAt || a.createdAt)).map(groupSummary),
    maxParticipants: GROUP_MAX_PARTICIPANTS, webhookFields: GROUP_FIELDS, configured: !!meta().phoneNumberId && !!meta().accessToken,
  });
});
// Ambil daftar grup aktif dari Meta (mis. grup yang dibuat sebelum fitur ini) lalu gabungkan berdasarkan ID grup
app.post('/api/groups/sync', requireAdmin, wrap(async (req, res) => {
  const seen = []; let after, pages = 0;
  do {
    const r = await graph('get', `${needPhone()}/groups`, { params: { limit: 100, after } });
    seen.push(...(r.data?.groups || r.data || []));
    after = r.paging?.next ? r.paging.cursors?.after : null;
  } while (after && ++pages < 50);
  let added = 0;
  for (const x of seen) {
    let g = groupByMeta(x.id);
    if (!g) { g = newGroup({ groupId: String(x.id), status: 'active', external: true, createdAt: Number(x.created_at) * 1000 || now() }); db.groups.push(g); added++; groupEvent(g, 'import', 'Diimpor dari Meta.'); }
    if (x.subject) g.subject = x.subject;
    if (g.status === 'creating' || g.status === 'deleted') g.status = 'active';
  }
  audit(req, 'group.sync', `${seen.length} grup aktif, ${added} baru`); save();
  res.json({ total: seen.length, added, groups: db.groups.map(groupSummary) });
}));
app.post('/api/groups', requireAdmin, wrap(async (req, res) => {
  const subject = str(req.body.subject, 128), description = str(req.body.description, 2048);
  if (!subject) throw new HttpError(400, 'Nama grup wajib diisi (maks. 128 karakter).');
  const joinApprovalMode = req.body.joinApprovalMode === 'approval_required' ? 'approval_required' : 'auto_approve';
  const r = await graph('post', `${needPhone()}/groups`, { data: { messaging_product: 'whatsapp', subject, ...(description ? { description } : {}), join_approval_mode: joinApprovalMode } });
  // Hasil akhir (ID grup & tautan undangan) datang lewat webhook group_lifecycle_update
  const g = newGroup({ subject, description, joinApprovalMode, requestId: r.request_id || null, groupId: r.group_id || null, createdBy: req.user.name });
  groupEvent(g, 'create_requested', `Permintaan pembuatan dikirim oleh ${req.user.name}. Menunggu konfirmasi Meta.`);
  db.groups.push(g); audit(req, 'group.create', subject); save();
  emitGroup(g);
  res.json(groupDetail(g));
}));
app.get('/api/groups/:id', requireAdmin, (req, res) => res.json(groupDetail(groupOr404(req.params.id))));
// Muat ulang info, tautan undangan, dan permintaan bergabung dari Meta
app.post('/api/groups/:id/refresh', requireAdmin, wrap(async (req, res) => {
  const g = groupOr404(req.params.id), gid = needActiveGroup(g);
  const info = await graph('get', gid, { params: { fields: 'subject,description,participants,join_approval_mode,suspended,creation_timestamp,total_participant_count' } });
  Object.assign(g, { subject: info.subject ?? g.subject, description: info.description ?? g.description, joinApprovalMode: info.join_approval_mode || g.joinApprovalMode, suspended: !!info.suspended });
  g.status = g.suspended ? 'suspended' : 'active';
  if (Array.isArray(info.participants)) {
    const prev = g.participants;
    g.participants = info.participants.map((p) => prev.find((x) => samePerson(x, p.wa_id)) || { waId: String(p.wa_id), phone: normPhone(p.wa_id), joinedAt: 0, via: 'sinkronisasi' });
  }
  const warn = [];
  try { g.inviteLink = (await graph('get', `${gid}/invite_link`)).invite_link || g.inviteLink; } catch (e) { warn.push('Tautan undangan: ' + e.message); }
  try {
    const jr = await graph('get', `${gid}/join_requests`);
    g.joinRequests = (jr.data || []).map((x) => ({ id: String(x.join_request_id), waId: String(x.wa_id || ''), at: Number(x.creation_timestamp) * 1000 || 0 }));
  } catch (e) { warn.push('Permintaan bergabung: ' + e.message); }
  g.syncedAt = now(); save(); emitGroup(g);
  res.json({ ...groupDetail(g), warnings: warn });
}));
app.patch('/api/groups/:id', requireAdmin, wrap(async (req, res) => {
  const g = groupOr404(req.params.id), gid = needActiveGroup(g);
  const data = { messaging_product: 'whatsapp' }, changes = [];
  if (req.body.subject !== undefined) { const s = str(req.body.subject, 128); if (!s) throw new HttpError(400, 'Nama grup tidak boleh kosong.'); if (s !== g.subject) { data.subject = s; changes.push('nama'); } }
  if (req.body.description !== undefined) { const d = str(req.body.description, 2048); if (d !== g.description) { data.description = d; changes.push('deskripsi'); } }
  if (!changes.length) throw new HttpError(400, 'Tidak ada perubahan.');
  await graph('post', gid, { data });
  // Nilai baru diterapkan saat webhook group_settings_update mengonfirmasi
  g.pending = { ...g.pending, ...(data.subject ? { subject: data.subject } : {}), ...(data.description !== undefined ? { description: data.description } : {}) };
  groupEvent(g, 'settings_requested', `Perubahan ${changes.join(' & ')} dikirim oleh ${req.user.name}. Menunggu konfirmasi Meta.`);
  audit(req, 'group.update', `${g.subject}: ${changes.join(', ')}`); save(); emitGroup(g);
  res.json(groupDetail(g));
}));
app.post('/api/groups/:id/photo', requireAdmin, wrap(async (req, res) => {
  const g = groupOr404(req.params.id), gid = needActiveGroup(g);
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(String(req.body.dataUrl || ''));
  if (!m) throw new HttpError(400, 'Foto grup harus JPEG.');
  const buf = Buffer.from(m[1], 'base64');
  if (buf.length > 5 * 1024 * 1024) throw new HttpError(400, 'Foto grup maksimal 5 MB.');
  const fd = new FormData();
  fd.append('messaging_product', 'whatsapp');
  fd.append('profile_picture_file', new Blob([buf], { type: 'image/jpeg' }), 'group.jpg');
  await graph('post', gid, { data: fd });
  g.photo = { data: m[1], status: 'pending', at: now() };
  groupEvent(g, 'settings_requested', `Foto grup dikirim oleh ${req.user.name}. Menunggu konfirmasi Meta.`);
  audit(req, 'group.photo', g.subject); save(); emitGroup(g);
  res.json(groupDetail(g));
}));
app.get('/api/groups/:id/photo', requireAdmin, (req, res) => {
  const g = groupOr404(req.params.id);
  if (!g.photo?.data) return res.sendStatus(404);
  res.set('Cache-Control', 'private, max-age=300').type('image/jpeg').send(Buffer.from(g.photo.data, 'base64'));
});
app.delete('/api/groups/:id', requireAdmin, wrap(async (req, res) => {
  const g = groupOr404(req.params.id);
  // Grup yang gagal dibuat / sudah dihapus di Meta: cukup hapus catatan lokal beserta pesannya
  if (!g.groupId || ['failed', 'deleted'].includes(g.status)) {
    db.groups.splice(db.groups.indexOf(g), 1);
    db.messages = db.messages.filter((m) => { if (m.groupId !== g.id) return true; if (m.wamid) idx.wamid.delete(m.wamid); return false; });
    audit(req, 'group.forget', g.subject); save();
    return res.json({ ok: true, removed: true });
  }
  await graph('delete', g.groupId);
  g.status = 'deleting';
  groupEvent(g, 'delete_requested', `Penghapusan diminta oleh ${req.user.name}. Menunggu konfirmasi Meta.`);
  audit(req, 'group.delete', g.subject); save(); emitGroup(g);
  res.json(groupDetail(g));
}));
app.post('/api/groups/:id/invite-link/reset', requireAdmin, wrap(async (req, res) => {
  const g = groupOr404(req.params.id), gid = needActiveGroup(g);
  const r = await graph('post', `${gid}/invite_link`, { data: { messaging_product: 'whatsapp' } });
  if (!r.invite_link) throw new HttpError(502, 'Meta tidak mengembalikan tautan undangan baru.');
  g.inviteLink = r.invite_link;
  groupEvent(g, 'invite_reset', `Tautan undangan diperbarui oleh ${req.user.name}. Tautan lama tidak berlaku lagi.`);
  audit(req, 'group.invite_reset', g.subject); save(); emitGroup(g);
  res.json(groupDetail(g));
}));
// Kirim tautan undangan ke kontak: pesan teks bila jendela 24 jam terbuka, selain itu wajib template APPROVED
app.post('/api/groups/:id/invite', requireAdmin, wrap(async (req, res) => {
  const g = groupOr404(req.params.id); needActiveGroup(g);
  if (!g.inviteLink) throw new HttpError(400, 'Tautan undangan belum tersedia. Klik Muat ulang dari Meta.');
  const ids = [...new Set((Array.isArray(req.body.contactIds) ? req.body.contactIds : []).map(String))].slice(0, 50);
  if (!ids.length) throw new HttpError(400, 'Pilih minimal satu kontak.');
  const text = str(req.body.text, 4000);
  const tpl = req.body.template?.name ? findTemplate(str(req.body.template.name, 512), str(req.body.template.language, 15)) : null;
  if (req.body.template?.name && (!tpl || tpl.status !== 'APPROVED')) throw new HttpError(400, 'Template undangan tidak ditemukan atau belum APPROVED.');
  const withLink = (v) => String(v ?? '').replace(/\{\{\s*link\s*\}\}/g, g.inviteLink);
  const results = [];
  for (const cid of ids) {
    const contact = byId('contacts', cid);
    if (!contact) { results.push({ contactId: cid, ok: false, error: 'Kontak tidak ditemukan.' }); continue; }
    const conv = getOrCreateConv(contact);
    const row = { contactId: cid, phone: contact.phone, name: contact.name || contact.waName || '' };
    try {
      if (windowOpen(conv) && text) {
        const body = fillVars(withLink(text.includes('{{link}}') ? text : `${text}\n\n{{link}}`), contact).slice(0, 4096);
        const r = await sendToMeta({ messaging_product: 'whatsapp', recipient_type: 'individual', to: contact.phone, type: 'text', text: { body, preview_url: true } },
          { source: 'inbox', contact, conversation: conv, userId: req.user.id, userName: req.user.name });
        addMessage(conv, { direction: 'out', type: 'text', content: { body }, wamid: r.messages?.[0]?.id, status: 'accepted', userId: req.user.id, userName: req.user.name });
        row.via = 'text';
      } else if (tpl) {
        const v = req.body.template.values || {};
        const base = (tpl.components || []).find((c) => c.type === 'BUTTONS')?.buttons || [];
        // Akhiran URL tombol: bila URL template "https://chat.whatsapp.com/{{1}}", isi dengan ID tautan saja
        const buttonUrl = base.map((btn) => {
          if (btn.type !== 'URL' || !/\{\{/.test(btn.url || '')) return '';
          const prefix = btn.url.replace(/\{\{.*$/, '');
          return g.inviteLink.startsWith(prefix) ? g.inviteLink.slice(prefix.length) : g.inviteLink;
        });
        await sendTemplateTo(contact, tpl, { header: (v.header || []).map(withLink), body: (v.body || []).map(withLink), headerMedia: v.headerMedia, buttonUrl },
          { userId: req.user.id, userName: req.user.name });
        row.via = 'template';
      } else throw new HttpError(400, 'Di luar jendela layanan 24 jam: pilih template undangan yang disetujui.');
      row.ok = true;
    } catch (e) { row.ok = false; row.error = e.message; }
    results.push(row);
    g.invites.push({ ...row, at: now(), by: req.user.name, joinedAt: g.participants.some((p) => p.phone === contact.phone) ? now() : null });
  }
  const sent = results.filter((r) => r.ok).length;
  groupEvent(g, 'invite_sent', `${req.user.name} mengirim undangan: ${sent} berhasil, ${results.length - sent} gagal.`);
  if (g.invites.length > 500) g.invites.splice(0, g.invites.length - 500);
  audit(req, 'group.invite', `${g.subject}: ${sent}/${results.length}`); save(); emitGroup(g);
  res.json({ results, group: groupDetail(g) });
}));
app.post('/api/groups/:id/participants/remove', requireAdmin, wrap(async (req, res) => {
  const g = groupOr404(req.params.id), gid = needActiveGroup(g);
  const users = [...new Set((Array.isArray(req.body.participants) ? req.body.participants : []).map((x) => str(String(x), 40)).filter(Boolean))];
  if (!users.length || users.length > GROUP_MAX_PARTICIPANTS) throw new HttpError(400, `Pilih 1–${GROUP_MAX_PARTICIPANTS} peserta.`);
  await graph('delete', `${gid}/participants`, { data: { messaging_product: 'whatsapp', participants: users.map((user) => ({ user })) } });
  g.pending = { ...g.pending, remove: users };
  groupEvent(g, 'remove_requested', `${req.user.name} meminta mengeluarkan ${users.map(personLabel).join(', ')}. Menunggu konfirmasi Meta.`);
  audit(req, 'group.participants_remove', `${g.subject}: ${users.length}`); save(); emitGroup(g);
  res.json(groupDetail(g));
}));
app.post('/api/groups/:id/join-requests/:action', requireAdmin, wrap(async (req, res) => {
  const g = groupOr404(req.params.id), gid = needActiveGroup(g);
  const approve = req.params.action === 'approve';
  if (!approve && req.params.action !== 'reject') throw new HttpError(404, 'Aksi tidak dikenal.');
  const ids = [...new Set((Array.isArray(req.body.ids) ? req.body.ids : []).map(String))].filter((id) => g.joinRequests.some((r) => r.id === id));
  if (!ids.length) throw new HttpError(400, 'Pilih permintaan bergabung.');
  const r = await graph(approve ? 'post' : 'delete', `${gid}/join_requests`, { data: { messaging_product: 'whatsapp', join_requests: ids } });
  const done = (approve ? r.approved_join_requests : r.rejected_join_requests) || [];
  const failed = r.failed_join_requests || [];
  const doneIds = new Set(done.map((x) => String(x.join_request_id || x)));
  // Yang disetujui masuk ke daftar peserta saat webhook group_participants_add tiba
  g.joinRequests = g.joinRequests.filter((x) => !doneIds.has(x.id));
  groupEvent(g, approve ? 'join_approved' : 'join_rejected', `${req.user.name} ${approve ? 'menyetujui' : 'menolak'} ${doneIds.size} permintaan bergabung${failed.length ? `, ${failed.length} gagal` : ''}.`);
  audit(req, 'group.join_' + req.params.action, `${g.subject}: ${doneIds.size}`); save(); emitGroup(g);
  res.json({ done: [...doneIds], failed, errors: metaErrText(r.errors), group: groupDetail(g) });
}));
app.post('/api/groups/:id/messages', requireAdmin, wrap(async (req, res) => {
  // Bila gagal, pesan tetap tercatat berstatus failed (lihat sendToGroup) dan error diteruskan ke pengirim
  res.json(await sendToGroup(groupOr404(req.params.id), req.body || {}, req.user));
}));
app.post('/api/groups/:id/read', requireAdmin, (req, res) => {
  const g = groupOr404(req.params.id);
  g.unread = 0; save();
  res.json({ ok: true });
});

/* CSAT */
// Rentang laporan: from/to berupa tanggal YYYY-MM-DD (inklusif), default 30 hari terakhir
function csatRange(q) {
  const day = (v) => (/^\d{4}-\d{2}-\d{2}$/.test(v || '') ? new Date(v + 'T00:00:00').getTime() : NaN);
  let to = day(q.to), from = day(q.from);
  const today = new Date(); today.setHours(0, 0, 0, 0);
  if (!Number.isFinite(to)) to = today.getTime();
  if (!Number.isFinite(from)) from = to - 29 * 86400000;
  if (from > to) throw new HttpError(400, 'Tanggal mulai harus sebelum tanggal selesai.');
  if (to - from > 365 * 86400000) throw new HttpError(400, 'Rentang maksimal 1 tahun.');
  return { from, to: to + 86400000 };
}
// Agen hanya melihat nilai miliknya sendiri
const csatAgentFilter = (req) => (req.user.role === 'admin' ? str(req.query.agent, 40) || null : req.user.id);
app.get('/api/csat/settings', requireAdmin, (req, res) => res.json(csatCfg().settings));
app.put('/api/csat/settings', requireAdmin, wrap(async (req, res) => {
  const s = validateCsat(req.body || {});
  csatCfg().settings = s;
  audit(req, 'csat.settings', `${s.enabled ? 'aktif' : 'nonaktif'}, skala ${s.scale}`); save();
  res.json(s);
}));
app.get('/api/csat/report', (req, res) => {
  const r = csatReport({ ...csatRange(req.query), agentId: csatAgentFilter(req) });
  res.json({ ...r, settings: req.user.role === 'admin' ? csatCfg().settings : { enabled: csatCfg().settings.enabled, scale: csatCfg().settings.scale } });
});
app.get('/api/csat/export', requireAdmin, (req, res) => {
  const { from, to } = csatRange(req.query), agentId = csatAgentFilter(req);
  const rows = csatCfg().surveys.filter((x) => x.sentAt >= from && x.sentAt < to && (!agentId || x.agentId === agentId));
  const iso = (t) => (t ? new Date(t).toISOString() : '');
  const STATUS = { sent: 'menunggu jawaban', answered: 'dijawab', expired: 'kedaluwarsa', failed: 'gagal', skipped: 'dilewati' };
  const lines = ['dikirim,nomor,kontak,agen,pemicu,status,skala,nilai,puas,komentar,dijawab,keterangan',
    ...rows.map((x) => [iso(x.sentAt), x.phone, byId('contacts', x.contactId)?.name || '', x.agentName, x.trigger, STATUS[x.status] || x.status, x.scale, x.score ?? '',
      x.status === 'answered' ? (x.satisfied ? 'ya' : 'tidak') : '', x.comment, iso(x.answeredAt), x.reason || ''].map(csvCell).join(','))];
  audit(req, 'csat.export', rows.length + ' baris');
  res.set('Content-Disposition', `attachment; filename="csat-${new Date(from).toISOString().slice(0, 10)}.csv"`).type('text/csv').send('﻿' + lines.join('\n'));
});
app.post('/api/conversations/:id/csat', wrap(async (req, res) => {
  const conv = convOr404(req);
  const survey = await sendCsat(conv, { trigger: 'manual', user: req.user });
  audit(req, 'csat.send', byId('contacts', conv.contactId)?.phone);
  res.json(csatPublic(survey));
}));

/* WhatsApp Flows (Meta). Daftar dapat dibaca semua pengguna (agen mengirim flow yang sudah terbit); pengelolaan khusus admin. */
const wafOr404 = (id) => { const f = wafById(id); if (!f) throw new HttpError(404, 'Flow tidak ditemukan. Sinkronkan dari Meta.'); return f; };
// Muat detail + Flow JSON terbaru dari Meta. JSON diunduh dari download_url aset (CDN Meta).
async function wafRefresh(f) {
  wafUpsert(await graph('get', f.id, { params: { fields: WAF_FIELDS } }));
  const assets = await graph('get', `${f.id}/assets`).catch(() => ({ data: [] }));
  const asset = (assets.data || []).find((a) => a.asset_type === 'FLOW_JSON');
  if (asset?.download_url && /^https:\/\//.test(asset.download_url)) {
    try {
      const r = await axios.get(asset.download_url, { responseType: 'text', timeout: 20000, maxContentLength: WAF_JSON_MAX, transformResponse: [(d) => d] });
      f.json = String(r.data);
    } catch (e) { console.warn('[waflow] unduh JSON gagal', e.message); }
  }
  save();
  return f;
}
function wafJsonOrThrow(text) {
  const json = typeof text === 'string' ? text : '';
  if (!json.trim()) throw new HttpError(400, 'Flow JSON kosong.');
  if (Buffer.byteLength(json) > WAF_JSON_MAX) throw new HttpError(400, 'Flow JSON maksimal 1 MB.');
  try { JSON.parse(json); } catch (e) { throw new HttpError(400, 'Flow JSON tidak valid: ' + e.message); }
  return json;
}
const wafCategories = (v) => {
  const cats = [...new Set((Array.isArray(v) ? v : []).filter((c) => WAF_CATEGORIES.includes(c)))];
  if (!cats.length) throw new HttpError(400, 'Pilih minimal satu kategori.');
  return cats;
};
app.get('/api/wa-flows', (req, res) => {
  const rows = db.waFlows.slice().sort((a, b) => String(a.name).localeCompare(String(b.name)));
  res.json({ categories: WAF_CATEGORIES, flows: rows.map((f) => (req.user.role === 'admin' ? wafPublic(f) : { id: f.id, name: f.name, status: f.status, screens: wafScreens(f.json) })) });
});
app.post('/api/wa-flows/sync', requireAdmin, wrap(async (req, res) => {
  const seen = []; let after, pages = 0;
  do {
    const r = await graph('get', `${needWaba()}/flows`, { params: { fields: WAF_FIELDS, limit: 100, after } });
    seen.push(...(r.data || []));
    after = r.paging?.next ? r.paging.cursors?.after : null;
  } while (after && ++pages < 20);
  const ids = new Set(seen.map((x) => String(x.id)));
  seen.forEach(wafUpsert);
  db.waFlows = db.waFlows.filter((f) => ids.has(f.id)); // flow yang sudah dihapus di Meta (jawaban yang tersimpan tetap ada)
  // Flow JSON dimuat untuk flow yang belum punya salinan lokal (dibutuhkan untuk memilih screen pertama)
  for (const f of db.waFlows.filter((x) => !x.json).slice(0, 30)) await wafRefresh(f).catch(() => {});
  audit(req, 'waflow.sync', `${seen.length} flow`); save();
  res.json({ total: seen.length, flows: db.waFlows.map((f) => wafPublic(f)) });
}));
app.get('/api/wa-flows/:id', requireAdmin, wrap(async (req, res) => {
  const f = wafOr404(req.params.id);
  if (req.query.refresh !== '0') await wafRefresh(f).catch((e) => { f.lastError = e.message; });
  res.json({ ...wafPublic(f, true), lastError: f.lastError || null });
}));
app.post('/api/wa-flows', requireAdmin, wrap(async (req, res) => {
  const name = str(req.body.name, 200);
  if (!name) throw new HttpError(400, 'Nama flow wajib diisi.');
  const data = { name, categories: wafCategories(req.body.categories) };
  if (req.body.cloneFlowId) data.clone_flow_id = String(wafOr404(req.body.cloneFlowId).id);
  else if (req.body.json) data.flow_json = wafJsonOrThrow(req.body.json);
  const r = await graph('post', `${needWaba()}/flows`, { data });
  // Flow dibuat sebagai DRAFT; error validasi JSON dikembalikan Meta tanpa menggagalkan pembuatan
  const f = wafUpsert({ id: r.id, name, categories: data.categories, status: 'DRAFT', validation_errors: r.validation_errors || [] });
  if (data.flow_json) f.json = data.flow_json;
  await wafRefresh(f).catch(() => {});
  audit(req, 'waflow.create', `${name}${data.clone_flow_id ? ' (salinan)' : ''}`); save();
  res.json(wafPublic(f, true));
}));
app.patch('/api/wa-flows/:id', requireAdmin, wrap(async (req, res) => {
  const f = wafOr404(req.params.id), data = {};
  if (req.body.name !== undefined) { data.name = str(req.body.name, 200); if (!data.name) throw new HttpError(400, 'Nama flow wajib diisi.'); }
  if (req.body.categories !== undefined) data.categories = wafCategories(req.body.categories);
  if (!Object.keys(data).length) throw new HttpError(400, 'Tidak ada perubahan.');
  await graph('post', f.id, { data });
  wafUpsert({ id: f.id, ...data });
  audit(req, 'waflow.update', f.name); save();
  res.json(wafPublic(f, true));
}));
// Unggah Flow JSON (hanya DRAFT). Meta mengembalikan validation_errors; flow tetap tersimpan sebagai draf.
app.put('/api/wa-flows/:id/json', requireAdmin, wrap(async (req, res) => {
  const f = wafOr404(req.params.id);
  if (f.status !== 'DRAFT') throw new HttpError(400, `Flow berstatus ${f.status} tidak dapat diubah. Gandakan (clone) untuk membuat versi baru.`);
  const json = wafJsonOrThrow(req.body.json);
  const fd = new FormData();
  fd.append('name', 'flow.json');
  fd.append('asset_type', 'FLOW_JSON');
  fd.append('file', new Blob([json], { type: 'application/json' }), 'flow.json');
  const r = await graph('post', `${f.id}/assets`, { data: fd });
  f.json = json; f.validationErrors = r.validation_errors || [];
  await wafRefresh(f).catch(() => {});
  f.json = json; // salinan yang baru diunggah, walau unduhan aset belum diperbarui CDN
  audit(req, 'waflow.json', `${f.name}: ${f.validationErrors.length} error validasi`); save();
  res.json(wafPublic(f, true));
}));
app.post('/api/wa-flows/:id/preview', requireAdmin, wrap(async (req, res) => {
  const f = wafOr404(req.params.id);
  const r = await graph('get', f.id, { params: { fields: `preview.invalidate(${req.body.invalidate ? 'true' : 'false'})` } });
  f.preview = r.preview ? { url: r.preview.preview_url, expiresAt: r.preview.expires_at } : null; save();
  res.json(f.preview || {});
}));
app.post('/api/wa-flows/:id/:action(publish|deprecate)', requireAdmin, wrap(async (req, res) => {
  const f = wafOr404(req.params.id), action = req.params.action;
  if (action === 'publish' && f.status !== 'DRAFT') throw new HttpError(400, 'Hanya flow DRAFT yang dapat diterbitkan.');
  if (action === 'publish' && f.validationErrors?.length) throw new HttpError(400, 'Perbaiki error validasi Flow JSON sebelum menerbitkan.');
  if (action === 'deprecate' && f.status !== 'PUBLISHED' && f.status !== 'THROTTLED') throw new HttpError(400, 'Hanya flow yang sudah terbit yang dapat dinonaktifkan.');
  await graph('post', `${f.id}/${action}`);
  await wafRefresh(f).catch(() => {});
  audit(req, 'waflow.' + action, f.name); save();
  res.json(wafPublic(f, true));
}));
app.delete('/api/wa-flows/:id', requireAdmin, wrap(async (req, res) => {
  const f = wafOr404(req.params.id);
  if (f.status !== 'DRAFT') throw new HttpError(400, 'Hanya flow DRAFT yang dapat dihapus. Flow yang sudah terbit hanya dapat dinonaktifkan (deprecate).');
  const used = db.flows.filter((x) => Object.values(x.nodes).some((n) => n.type === 'waflow' && n.cfg.flowId === f.id)).map((x) => x.name);
  if (used.length) throw new HttpError(400, `Flow masih dipakai di Flow otomatis: ${used.join(', ')}.`);
  await graph('delete', f.id);
  db.waFlows = db.waFlows.filter((x) => x.id !== f.id);
  audit(req, 'waflow.delete', f.name); save();
  res.json({ ok: true });
}));
// Jawaban formulir per flow (isian disimpan apa adanya dari response_json)
function wafResponseRows(flowId) {
  return wafSubmissions(flowId).slice().reverse().map((s) => {
    const contact = byId('contacts', s.contactId);
    return { id: s.id, status: s.status, sentAt: s.sentAt, completedAt: s.completedAt, via: s.via, mode: s.mode, sentBy: s.sentBy,
      conversationId: s.conversationId, contact: contact ? contactLabel(contact) : '', phone: contact?.phone || '', response: s.response || null };
  });
}
app.get('/api/wa-flows/:id/responses', requireAdmin, (req, res) => {
  const rows = wafResponseRows(req.params.id);
  res.json({ total: rows.length, completed: rows.filter((r) => r.status === 'completed').length, rows: rows.slice(0, 500) });
});
app.get('/api/wa-flows/:id/responses.csv', requireAdmin, (req, res) => {
  const rows = wafResponseRows(req.params.id).filter((r) => r.status === 'completed');
  const keys = [...new Set(rows.flatMap((r) => Object.keys(r.response || {})))];
  const cell = (v) => csvCell(v && typeof v === 'object' ? JSON.stringify(v) : v);
  const iso = (t) => (t ? new Date(t).toISOString() : '');
  const lines = [['diisi', 'dikirim', 'nomor', 'kontak', 'cara_kirim', ...keys].map(csvCell).join(','),
    ...rows.map((r) => [iso(r.completedAt), iso(r.sentAt), r.phone, r.contact, r.via, ...keys.map((k) => r.response?.[k])].map(cell).join(','))];
  audit(req, 'waflow.export', `${req.params.id}: ${rows.length} baris`);
  res.set('Content-Disposition', `attachment; filename="flow-${req.params.id}.csv"`).type('text/csv').send('﻿' + lines.join('\n'));
});
app.get('/api/audit', requireAdmin, (req, res) => {
  const q = str(req.query.q, 100).toLowerCase();
  let rows = db.audit.slice().reverse();
  if (q) rows = rows.filter((a) => `${a.action} ${a.detail} ${a.userName} ${a.ip}`.toLowerCase().includes(q));
  res.json(rows.slice(0, 500));
});

/* Dashboard & laporan */
/* Meta Cost Monitor (admin)
 * Sumber 1: biaya resmi dari Pricing Analytics API (GET /{waba-id}?fields=pricing_analytics...). Bisa tertunda dari Meta.
 * Sumber 2: estimasi realtime = jumlah pesan berbayar dari webhook status (pricing.billable) × tarif yang diisi admin.
 */
const COST_CATS = ['marketing', 'utility', 'authentication', 'authentication_international', 'service', 'marketing_lite', 'referral_conversion'];
const costCfg = () => (db.costs = db.costs || { settings: { budget: 0, alertPct: 80, currency: '', rates: {} }, months: {} });
function monthBounds(m) {
  const [y, mo] = (/^\d{4}-\d{2}$/.test(m || '') ? m : new Date().toISOString().slice(0, 7)).split('-').map(Number);
  const start = Date.UTC(y, mo - 1, 1), end = Date.UTC(y, mo, 1);
  return { key: `${y}-${String(mo).padStart(2, '0')}`, start, end, days: Math.round((end - start) / 86400000) };
}
app.get('/api/costs', requireAdmin, (req, res) => {
  const cfg = costCfg(), mb = monthBounds(req.query.month);
  const currency = cfg.settings.currency || db.settings.connection?.waba?.currency || '';
  const dayKey = (t) => new Date(t).toISOString().slice(0, 10);
  const dayList = Array.from({ length: mb.days }, (_, i) => dayKey(mb.start + i * 86400000));
  // Webhook: pesan keluar yang sudah membawa info pricing pada bulan ini
  const wh = {}, whDaily = Object.fromEntries(dayList.map((d) => [d, 0]));
  for (const m of db.messages) {
    if (m.direction !== 'out' || !m.pricing) continue;
    const t = m.pricing.at || m.timestamp;
    if (t < mb.start || t >= mb.end) continue;
    const cat = m.pricing.category || 'lainnya';
    const row = (wh[cat] = wh[cat] || { billable: 0, free: 0 });
    if (m.pricing.billable) { row.billable++; whDaily[dayKey(t)]++; } else row.free++;
  }
  const rates = cfg.settings.rates || {};
  const estimate = Object.entries(wh).reduce((sum, [cat, x]) => sum + x.billable * (Number(rates[cat]) || 0), 0);
  // Meta: data hasil sinkronisasi terakhir
  const mm = cfg.months[mb.key];
  const metaCat = {}, metaDaily = Object.fromEntries(dayList.map((d) => [d, 0]));
  let metaTotal = 0, metaVolume = 0;
  for (const p of mm?.points || []) {
    const c = (metaCat[p.category] = metaCat[p.category] || { cost: 0, volume: 0 });
    c.cost += p.cost; c.volume += p.volume; metaTotal += p.cost; metaVolume += p.volume;
    if (p.date in metaDaily) metaDaily[p.date] += p.cost;
  }
  const today = dayKey(now()), isCurrent = today >= dayList[0] && today <= dayList[dayList.length - 1];
  const elapsed = isCurrent ? dayList.indexOf(today) + 1 : mb.days;
  const spent = mm?.points?.length ? metaTotal : estimate;
  res.json({
    month: mb.key, currency, isCurrent, daysElapsed: elapsed, daysInMonth: mb.days,
    settings: { ...cfg.settings, currency: cfg.settings.currency || '' }, defaultCurrency: db.settings.connection?.waba?.currency || '',
    webhook: { byCategory: wh, billable: Object.values(wh).reduce((n, x) => n + x.billable, 0), free: Object.values(wh).reduce((n, x) => n + x.free, 0), estimate, daily: dayList.map((d) => ({ date: d, count: whDaily[d] })) },
    meta: mm ? { syncedAt: mm.syncedAt, error: mm.error || null, total: metaTotal, volume: metaVolume, byCategory: metaCat, daily: dayList.map((d) => ({ date: d, cost: metaDaily[d] })), hasData: !!mm.points?.length } : null,
    spent, spentSource: mm?.points?.length ? 'meta' : 'estimate',
    projected: isCurrent && elapsed ? (spent / elapsed) * mb.days : spent,
  });
});
app.post('/api/costs/sync', requireAdmin, wrap(async (req, res) => {
  const cfg = costCfg(), mb = monthBounds(req.body.month);
  const end = Math.min(mb.end, now());
  if (end <= mb.start) throw new HttpError(400, 'Bulan ini belum dimulai.');
  const fields = `pricing_analytics.start(${Math.floor(mb.start / 1000)}).end(${Math.floor(end / 1000)}).granularity(DAILY).dimensions(["PRICING_CATEGORY","PRICING_TYPE"])`;
  try {
    const r = await graph('get', needWaba(), { params: { fields } });
    const pts = (r.pricing_analytics?.data || []).flatMap((x) => x.data_points || []);
    cfg.months[mb.key] = {
      syncedAt: now(), error: null,
      points: pts.map((p) => ({ date: new Date(Number(p.start) * 1000).toISOString().slice(0, 10), category: String(p.pricing_category || 'unknown').toLowerCase(), type: String(p.pricing_type || '').toLowerCase(), volume: Number(p.volume) || 0, cost: Number(p.cost) || 0 })),
    };
    audit(req, 'costs.sync', `${mb.key}: ${pts.length} titik data`); save();
    res.json({ ok: true, points: pts.length });
  } catch (e) {
    cfg.months[mb.key] = { ...(cfg.months[mb.key] || {}), syncedAt: now(), error: e.message };
    save(); throw e;
  }
}));
app.put('/api/costs/settings', requireAdmin, wrap(async (req, res) => {
  const cfg = costCfg(), b = req.body || {};
  const num = (v, name) => { const n = Number(v || 0); if (!Number.isFinite(n) || n < 0 || n > 1e12) throw new HttpError(400, `${name} tidak valid.`); return n; };
  const currency = str(b.currency, 3).toUpperCase();
  if (currency && !/^[A-Z]{3}$/.test(currency)) throw new HttpError(400, 'Kode mata uang harus 3 huruf (mis. IDR, USD).');
  const alertPct = num(b.alertPct ?? 80, 'Ambang peringatan');
  if (alertPct < 1 || alertPct > 100) throw new HttpError(400, 'Ambang peringatan harus 1–100%.');
  cfg.settings = { budget: num(b.budget, 'Anggaran'), alertPct, currency, rates: Object.fromEntries(COST_CATS.map((c) => [c, num(b.rates?.[c], 'Tarif ' + c)]).filter(([, v]) => v > 0)) };
  audit(req, 'costs.settings', `anggaran ${cfg.settings.budget} ${currency || ''}`); save();
  res.json(cfg.settings);
}));
/* Log pesan API (admin): semua pesan keluar via Cloud API + status pengiriman dari webhook */
const LOG_SOURCES = { inbox: 'Dashboard', campaign: 'Campaign', auto_reply: 'Auto reply', flow: 'Flow otomatis', group: 'Grup', csat: 'Survei CSAT', external: 'Di luar Kontaq' };
function logRow(e) {
  const msg = e.wamid ? idx.wamid.get(e.wamid) : null;
  const contact = e.contactId ? byId('contacts', e.contactId) : idx.contactByPhone.get(e.to);
  const hist = (msg || e).statusHistory || [];
  const pricing = msg?.pricing || e.pricing || null;
  return {
    id: e.id, at: e.at, source: e.source, userName: e.userName, campaignId: e.campaignId, campaignName: e.campaignName,
    to: e.to, contactName: contact?.name || contact?.waName || '', conversationId: e.conversationId || msg?.conversationId || null,
    type: e.type, summary: e.summary, templateName: e.templateName, templateCategory: e.templateCategory || (pricing?.category ?? ''),
    wamid: e.wamid, requestOk: e.ok, httpStatus: e.http?.status ?? null, messageStatus: e.response?.messageStatus || null,
    status: deliveryState(e, msg), sentAt: (msg || e).sentAt || null, deliveredAt: (msg || e).deliveredAt || null, readAt: (msg || e).readAt || null,
    failedAt: (msg || e).failedAt || null, error: e.error?.message || hist.filter((h) => h.status === 'failed').flatMap((h) => h.errors || []).map((x) => `${x.title} (${x.code})`).join('; ') || null,
    pricing, cost: estimateCost(pricing), backfilled: !!e.backfilled,
  };
}
function filterLog(q) {
  const from = q.from ? Date.parse(q.from + 'T00:00:00') : 0;
  const to = q.to ? Date.parse(q.to + 'T23:59:59.999') : Infinity;
  const term = str(q.q, 100).toLowerCase(), termDigits = normPhone(term);
  const types = q.type === 'media' ? ['image', 'video', 'audio', 'document', 'sticker'] : q.type ? [q.type] : null;
  const rows = [];
  for (let i = db.sendLog.length - 1; i >= 0; i--) {
    const e = db.sendLog[i];
    if (e.at < from || e.at > to) continue;
    if (q.source && e.source !== q.source) continue;
    if (types && !types.includes(e.type)) continue;
    if (q.campaignId && e.campaignId !== q.campaignId) continue;
    if (q.template && e.templateName !== q.template) continue;
    if (q.phoneNumberId && e.phoneNumberId !== q.phoneNumberId) continue;
    if (term && !(String(e.wamid || '').toLowerCase().includes(term) || (termDigits.length >= 4 && e.to.includes(termDigits)))) continue;
    const row = logRow(e);
    if (q.status && row.status !== q.status) continue;
    if (q.failed === '1' && row.status !== 'failed') continue;
    rows.push(row);
  }
  return rows;
}
function logTotals(rows) {
  const t = { all: rows.length, byStatus: { accepted: 0, sent: 0, delivered: 0, read: 0, failed: 0 }, bySource: {}, byType: {}, requestFailed: 0, cost: { amount: 0, billable: 0, free: 0, unknownRate: 0, noPricing: 0 } };
  for (const r of rows) {
    t.byStatus[r.status] = (t.byStatus[r.status] || 0) + 1;
    t.bySource[r.source] = (t.bySource[r.source] || 0) + 1;
    t.byType[r.type] = (t.byType[r.type] || 0) + 1;
    if (!r.requestOk) t.requestFailed++;
    if (!r.pricing) t.cost.noPricing++;
    else if (!r.cost.billable) t.cost.free++;
    else { t.cost.billable++; if (r.cost.known) t.cost.amount += r.cost.amount; else t.cost.unknownRate++; }
  }
  return t;
}
app.get('/api/message-log', requireAdmin, (req, res) => {
  const rows = filterLog(req.query);
  const per = Math.min(200, Math.max(10, Number(req.query.per) || 50));
  const pages = Math.max(1, Math.ceil(rows.length / per));
  const page = Math.min(pages, Math.max(1, Number(req.query.page) || 1));
  res.json({
    rows: rows.slice((page - 1) * per, page * per), total: rows.length, page, per, pages, totals: logTotals(rows),
    currency: costCfg().settings.currency || db.settings.connection?.waba?.currency || '',
    options: {
      sources: LOG_SOURCES,
      campaigns: db.campaigns.map((c) => ({ id: c.id, name: c.name })).reverse(),
      templates: [...new Set(db.sendLog.map((e) => e.templateName).filter(Boolean))].sort(),
      phoneNumberIds: [...new Set(db.sendLog.map((e) => e.phoneNumberId).filter(Boolean))],
    },
  });
});
app.get('/api/message-log/export.csv', requireAdmin, (req, res) => {
  const rows = filterLog(req.query);
  const head = ['waktu', 'penerima', 'nama_kontak', 'jenis', 'isi_atau_template', 'sumber', 'pengirim', 'campaign', 'message_id', 'http', 'status', 'sent_at', 'delivered_at', 'read_at', 'error', 'kategori_biaya', 'estimasi_biaya'];
  const iso = (t) => (t ? new Date(t).toISOString() : '');
  const lines = [head.join(',')].concat(rows.map((r) => [iso(r.at), r.to, r.contactName, r.type, r.templateName || r.summary, LOG_SOURCES[r.source] || r.source, r.userName, r.campaignName, r.wamid, r.httpStatus,
    r.status, iso(r.sentAt), iso(r.deliveredAt), iso(r.readAt), r.error, r.pricing?.category || '', r.cost.billable ? (r.cost.known ? r.cost.amount : 'tarif belum diisi') : r.pricing ? 0 : ''].map(csvCell).join(',')));
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="log-pesan-${new Date().toISOString().slice(0, 10)}.csv"`);
  audit(req, 'message_log.export', `${rows.length} baris`);
  res.send('﻿' + lines.join('\n'));
});
app.get('/api/message-log/:id', requireAdmin, (req, res) => {
  const e = db.sendLog.find((x) => x.id === req.params.id);
  if (!e) throw new HttpError(404, 'Log tidak ditemukan.');
  const msg = e.wamid ? idx.wamid.get(e.wamid) : null;
  res.json({
    ...logRow(e), phoneNumberId: e.phoneNumberId, wabaId: e.wabaId, graphVersion: e.graphVersion, templateLanguage: e.templateLanguage,
    request: e.request, http: e.http, response: e.response, errorDetail: e.error, statusHistory: (msg || e).statusHistory || [],
  });
});

app.get('/api/stats', (req, res) => {
  const days = Math.min(90, Math.max(7, Number(req.query.days) || 14));
  const start = new Date(); start.setHours(0, 0, 0, 0); start.setDate(start.getDate() - (days - 1));
  const series = Array.from({ length: days }, (_, i) => { const d = new Date(start); d.setDate(d.getDate() + i); return { date: d.toISOString().slice(0, 10), t: d.getTime(), in: 0, out: 0 }; });
  const st = { accepted: 0, sent: 0, delivered: 0, read: 0, failed: 0, pending: 0 };
  for (const m of db.messages) {
    if (m.timestamp < start.getTime()) continue;
    const i = Math.floor((m.timestamp - start.getTime()) / 86400000);
    if (series[i]) series[i][m.direction]++;
    if (m.direction === 'out') st[m.status === 'played' ? 'read' : m.status] = (st[m.status] || 0) + 1;
  }
  const convs = db.conversations.filter((c) => canSeeConv(req.user, c));
  const agents = db.users.filter((u) => u.active).map((u) => ({
    id: u.id, name: u.name, role: u.role,
    open: db.conversations.filter((c) => c.assignedTo === u.id && c.status !== 'closed').length,
    closed: db.conversations.filter((c) => c.assignedTo === u.id && c.status === 'closed').length,
    sent: db.messages.filter((m) => m.userId === u.id && m.timestamp >= start.getTime()).length,
  }));
  res.json({
    days, series: series.map(({ t, ...r }) => r), outbound: st,
    conversations: {
      open: convs.filter((c) => c.status === 'open').length, pending: convs.filter((c) => c.status === 'pending').length,
      closed: convs.filter((c) => c.status === 'closed').length, unassigned: convs.filter((c) => !c.assignedTo && c.status !== 'closed').length,
      windowOpen: convs.filter(windowOpen).length,
    },
    contacts: db.contacts.length, templates: { total: db.templates.length, approved: db.templates.filter((t) => t.status === 'APPROVED').length },
    campaigns: db.campaigns.slice(-5).reverse().map(campaignSummary),
    agents: req.user.role === 'admin' ? agents : agents.filter((a) => a.id === req.user.id),
    connected: !!meta().accessToken && !!meta().phoneNumberId,
  });
});

/* Kontak */
function contactLabels() { return [...new Set(db.contacts.flatMap((c) => c.labels || []))].sort(); }
const cleanLabels = (v) => [...new Set((Array.isArray(v) ? v : String(v || '').split(/[|,]/)).map((l) => str(l, 32)).filter(Boolean))].slice(0, 20);

app.get('/api/contacts', (req, res) => {
  const q = str(req.query.q, 100).toLowerCase(), label = str(req.query.label, 32);
  let rows = db.contacts;
  if (q) rows = rows.filter((c) => `${c.name} ${c.waName} ${c.phone} ${c.notes} ${(c.labels || []).join(' ')}`.toLowerCase().includes(q));
  if (label) rows = rows.filter((c) => (c.labels || []).includes(label));
  rows = rows.slice().sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  const page = Math.max(1, Number(req.query.page) || 1), per = 50;
  res.json({ total: rows.length, page, per, rows: rows.slice((page - 1) * per, page * per).map((c) => ({ ...c, conversationId: idx.convByContact.get(c.id)?.id || null })), labels: contactLabels() });
});
app.post('/api/contacts', wrap(async (req, res) => {
  const phone = normPhone(req.body.phone);
  if (!validPhone(phone)) throw new HttpError(400, 'Nomor harus format internasional, 8–15 digit (contoh: 6281234567890).');
  if (idx.contactByPhone.has(phone)) throw new HttpError(400, 'Nomor sudah ada di kontak.');
  const c = getOrCreateContact(phone);
  Object.assign(c, { name: str(req.body.name, 120), labels: cleanLabels(req.body.labels), notes: str(req.body.notes, 2000), optIn: !!req.body.optIn });
  audit(req, 'contact.create', phone); save();
  res.json(c);
}));
app.patch('/api/contacts/:id', wrap(async (req, res) => {
  const c = byId('contacts', req.params.id);
  if (!c) throw new HttpError(404, 'Kontak tidak ditemukan.');
  const b = req.body;
  if (b.name !== undefined) c.name = str(b.name, 120);
  if (b.labels !== undefined) c.labels = cleanLabels(b.labels);
  if (b.notes !== undefined) c.notes = str(b.notes, 2000);
  if (b.optIn !== undefined) c.optIn = !!b.optIn;
  c.updatedAt = now(); save();
  const conv = idx.convByContact.get(c.id);
  if (conv) emitConv(conv, 'conversation:update', serializeConv(conv));
  res.json(c);
}));
/* Foto profil kontak (diunggah agen; WhatsApp Cloud API tidak menyediakan foto profil pengguna) */
app.get('/api/contacts/:id/avatar', (req, res) => {
  const a = db.avatars[req.params.id];
  if (!a) return res.sendStatus(404);
  res.set('Cache-Control', 'private, max-age=86400').type(a.mime).send(Buffer.from(a.data, 'base64'));
});
app.put('/api/contacts/:id/avatar', wrap(async (req, res) => {
  const c = byId('contacts', req.params.id);
  if (!c) throw new HttpError(404, 'Kontak tidak ditemukan.');
  const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(req.body.dataUrl || ''));
  if (!m) throw new HttpError(400, 'Format foto tidak valid (JPEG/PNG/WebP).');
  if (m[2].length > 200 * 1024) throw new HttpError(400, 'Foto terlalu besar (maks. ~150 KB setelah dikompres).');
  db.avatars[c.id] = { mime: m[1], data: m[2] };
  c.avatarV = now(); c.updatedAt = now();
  audit(req, 'contact.avatar', c.phone); save();
  const conv = idx.convByContact.get(c.id);
  if (conv) emitConv(conv, 'conversation:update', serializeConv(conv));
  res.json({ avatarV: c.avatarV });
}));
app.delete('/api/contacts/:id/avatar', wrap(async (req, res) => {
  const c = byId('contacts', req.params.id);
  if (!c) throw new HttpError(404, 'Kontak tidak ditemukan.');
  delete db.avatars[c.id]; c.avatarV = 0; c.updatedAt = now();
  audit(req, 'contact.avatar.delete', c.phone); save();
  const conv = idx.convByContact.get(c.id);
  if (conv) emitConv(conv, 'conversation:update', serializeConv(conv));
  res.json({ avatarV: 0 });
}));
// Ringkasan profil pelanggan untuk panel info & layar panggilan
app.get('/api/contacts/:id/profile', (req, res) => {
  const c = byId('contacts', req.params.id);
  if (!c) return res.status(404).json({ error: 'Kontak tidak ditemukan.' });
  const conv = idx.convByContact.get(c.id);
  const visible = conv && canSeeConv(req.user, conv);
  const msgs = visible ? db.messages.filter((m) => m.conversationId === conv.id) : [];
  const calls = db.calls.filter((x) => x.contactId === c.id);
  const done = calls.filter((x) => !['ringing', 'calling'].includes(x.status));
  res.json({
    contact: c,
    conversation: visible ? { id: conv.id, status: conv.status, assignedName: conv.assignedTo ? byId('users', conv.assignedTo)?.name || null : null, windowOpen: !!windowOpen(conv), notes: (conv.notes || []).length, lastMessageAt: conv.lastMessageAt, preview: conv.preview } : null,
    stats: {
      since: Math.min(c.createdAt || now(), msgs[0]?.timestamp || now()),
      messagesIn: msgs.filter((m) => m.direction === 'in').length,
      messagesOut: msgs.filter((m) => m.direction === 'out').length,
      lastInboundAt: visible ? conv.lastInboundAt || 0 : 0,
      calls: done.length,
      missed: done.filter((x) => x.direction === 'USER_INITIATED' && !x.answeredAt).length,
      lastCallAt: calls.length ? Math.max(...calls.map((x) => x.startedAt)) : 0,
    },
  });
});
app.delete('/api/contacts/:id', requireAdmin, wrap(async (req, res) => {
  const c = byId('contacts', req.params.id);
  if (!c) throw new HttpError(404, 'Kontak tidak ditemukan.');
  const conv = idx.convByContact.get(c.id);
  db.contacts = db.contacts.filter((x) => x.id !== c.id);
  delete db.avatars[c.id];
  if (conv) { db.conversations = db.conversations.filter((x) => x.id !== conv.id); db.messages = db.messages.filter((m) => m.conversationId !== conv.id); }
  reindex(); audit(req, 'contact.delete', c.phone); save();
  res.json({ ok: true });
}));
app.post('/api/contacts/import', requireAdmin, upload.single('file'), wrap(async (req, res) => {
  if (!req.file) throw new HttpError(400, 'File CSV wajib diunggah.');
  const rows = parseCsv(req.file.buffer.toString('utf8').replace(/^﻿/, ''));
  if (!rows.length) throw new HttpError(400, 'CSV kosong.');
  const head = rows[0].map((h) => h.trim().toLowerCase());
  const col = (names) => head.findIndex((h) => names.includes(h));
  const iPhone = col(['phone', 'nomor', 'no', 'whatsapp', 'wa', 'telepon']);
  if (iPhone < 0) throw new HttpError(400, 'Kolom "phone" tidak ditemukan pada baris header.');
  const iName = col(['name', 'nama']), iLabels = col(['labels', 'label', 'tags']), iNotes = col(['notes', 'catatan']), iOpt = col(['opt_in', 'optin', 'opt-in']);
  const extraLabels = cleanLabels(req.body.labels);
  let created = 0, updated = 0; const errors = [];
  rows.slice(1).forEach((r, n) => {
    const phone = normPhone(r[iPhone]);
    if (!validPhone(phone)) { errors.push(`Baris ${n + 2}: nomor tidak valid "${r[iPhone] || ''}"`); return; }
    const exists = idx.contactByPhone.has(phone);
    const c = getOrCreateContact(phone);
    if (iName >= 0 && r[iName]) c.name = str(r[iName], 120);
    c.labels = cleanLabels([...(c.labels || []), ...(iLabels >= 0 ? cleanLabels(r[iLabels]) : []), ...extraLabels]);
    if (iNotes >= 0 && r[iNotes]) c.notes = str(r[iNotes], 2000);
    if (iOpt >= 0) c.optIn = /^(1|true|ya|yes|y)$/i.test(String(r[iOpt]).trim());
    c.updatedAt = now();
    exists ? updated++ : created++;
  });
  audit(req, 'contact.import', `${created} baru, ${updated} diperbarui, ${errors.length} error`); save();
  res.json({ created, updated, errors: errors.slice(0, 50), errorCount: errors.length });
}));
app.get('/api/contacts/export.csv', requireAdmin, (req, res) => {
  const lines = ['phone,name,labels,notes,opt_in', ...db.contacts.map((c) => [c.phone, c.name, (c.labels || []).join('|'), c.notes, c.optIn ? 1 : 0].map(csvCell).join(','))];
  audit(req, 'contact.export', `${db.contacts.length} kontak`);
  res.type('text/csv').attachment('kontaq-contacts.csv').send('﻿' + lines.join('\n'));
});

/* Percakapan / Inbox */
app.get('/api/conversations', (req, res) => {
  const q = str(req.query.q, 100).toLowerCase(), status = str(req.query.status, 20), scope = str(req.query.scope, 20);
  let rows = db.conversations.filter((c) => canSeeConv(req.user, c) && c.lastMessageAt);
  if (status && status !== 'all') rows = rows.filter((c) => c.status === status);
  if (scope === 'mine') rows = rows.filter((c) => c.assignedTo === req.user.id);
  if (scope === 'unassigned') rows = rows.filter((c) => !c.assignedTo);
  let out = rows.map(serializeConv);
  if (q) out = out.filter((c) => `${c.contact.name} ${c.contact.waName} ${c.contact.phone} ${c.preview} ${(c.contact.labels || []).join(' ')}`.toLowerCase().includes(q));
  out.sort((a, b) => b.lastMessageAt - a.lastMessageAt);
  res.json(out.slice(0, 300));
});
app.post('/api/conversations', wrap(async (req, res) => {
  // Mulai percakapan dari kontak (tanpa pesan); pesan pertama wajib template bila di luar jendela 24 jam
  const contact = byId('contacts', req.body.contactId);
  if (!contact) throw new HttpError(404, 'Kontak tidak ditemukan.');
  const conv = getOrCreateConv(contact);
  if (!canSeeConv(req.user, conv)) throw new HttpError(403, 'Percakapan ini ditangani agen lain.');
  if (!conv.lastMessageAt) conv.lastMessageAt = now();
  save();
  res.json(serializeConv(conv));
}));
app.get('/api/conversations/:id', wrap(async (req, res) => {
  const conv = convOr404(req);
  const before = Number(req.query.before) || Infinity;
  const msgs = db.messages.filter((m) => m.conversationId === conv.id && m.timestamp < before);
  res.json({ conversation: serializeConv(conv), messages: msgs.slice(-100), hasMore: msgs.length > 100 });
}));
app.post('/api/conversations/:id/read', wrap(async (req, res) => {
  const conv = convOr404(req);
  const hadUnread = conv.unread > 0;
  conv.unread = 0; save();
  emitConv(conv, 'conversation:update', serializeConv(conv));
  // Tandai dibaca di WhatsApp (centang biru) untuk pesan masuk terakhir
  if (hadUnread) {
    const last = db.messages.filter((m) => m.conversationId === conv.id && m.direction === 'in' && m.wamid).pop();
    if (last && now() - last.timestamp < 30 * 24 * 3600 * 1000) {
      graph('post', `${needPhone()}/messages`, { data: { messaging_product: 'whatsapp', status: 'read', message_id: last.wamid } }).catch((e) => console.warn('[read]', e.message));
    }
  }
  res.json({ ok: true });
}));
app.patch('/api/conversations/:id', wrap(async (req, res) => {
  const conv = convOr404(req);
  const b = req.body, changes = [];
  let closing = false;
  if (b.status !== undefined) {
    if (!['open', 'pending', 'closed'].includes(b.status)) throw new HttpError(400, 'Status tidak valid.');
    if (b.status === 'closed' && conv.status !== 'closed') closing = true;
    conv.status = b.status; changes.push('status=' + b.status);
  }
  if (b.assignedTo !== undefined) {
    const target = b.assignedTo ? byId('users', b.assignedTo) : null;
    if (b.assignedTo && (!target || !target.active)) throw new HttpError(400, 'Agen tidak valid.');
    // Agen hanya bisa mengambil untuk diri sendiri atau melepas miliknya
    if (req.user.role !== 'admin' && b.assignedTo && b.assignedTo !== req.user.id) throw new HttpError(403, 'Agen hanya dapat menugaskan ke diri sendiri.');
    const prev = conv.assignedTo;
    conv.assignedTo = target?.id || null; changes.push('assign=' + (target?.name || '-'));
    // Beri tahu pemilik sebelumnya agar daftar mereka diperbarui
    if (prev && prev !== conv.assignedTo) io?.to('user:' + prev).emit('conversation:removed', { id: conv.id });
    if (target && target.id !== prev && target.id !== req.user.id) notifyAssigned(conv, target, req.user);
  }
  audit(req, 'conversation.update', `${byId('contacts', conv.contactId)?.phone}: ${changes.join(', ')}`); save();
  emitConv(conv, 'conversation:update', serializeConv(conv));
  if (closing) maybeSendCsat(conv, 'close', req.user);
  res.json(serializeConv(conv));
}));
app.post('/api/conversations/:id/notes', wrap(async (req, res) => {
  const conv = convOr404(req);
  const text = str(req.body.text, 2000);
  if (!text) throw new HttpError(400, 'Catatan kosong.');
  const note = { id: uid('n_'), text, userId: req.user.id, userName: req.user.name, at: now() };
  conv.notes = conv.notes || []; conv.notes.push(note); save();
  emitConv(conv, 'conversation:update', serializeConv(conv));
  res.json(note);
}));
app.delete('/api/conversations/:id/notes/:noteId', wrap(async (req, res) => {
  const conv = convOr404(req);
  const note = (conv.notes || []).find((n) => n.id === req.params.noteId);
  if (!note) throw new HttpError(404, 'Catatan tidak ditemukan.');
  if (note.userId !== req.user.id && req.user.role !== 'admin') throw new HttpError(403, 'Hanya penulis atau admin yang dapat menghapus.');
  conv.notes = conv.notes.filter((n) => n.id !== note.id); save();
  emitConv(conv, 'conversation:update', serializeConv(conv));
  res.json({ ok: true });
}));

/* Kirim pesan */
app.post('/api/media', upload.single('file'), wrap(async (req, res) => {
  const kind = str(req.body.kind, 20);
  const rule = MEDIA_RULES[kind];
  if (!rule || !req.file) throw new HttpError(400, 'File dan jenis media wajib diisi.');
  const file = req.file, ext = path.extname(file.originalname || '').slice(1).toLowerCase();
  const baseMime = String(file.mimetype || '').split(';')[0].toLowerCase();
  if (kind === 'document' && (!baseMime || baseMime === 'application/octet-stream') && DOC_MIMES[ext]) file.mimetype = DOC_MIMES[ext];
  else file.mimetype = baseMime || file.mimetype;
  if (rule.mimes && !rule.mimes.includes(file.mimetype)) throw new HttpError(400, `Format ${file.mimetype || 'tidak dikenal'} tidak didukung untuk ${kind}. Didukung: ${rule.mimes.join(', ')}`);
  if (file.size > rule.max * 1024 * 1024) throw new HttpError(400, `Ukuran maksimal ${kind}: ${rule.max >= 1 ? rule.max + ' MB' : rule.max * 1024 + ' KB'}.`);
  const extra = {};
  if (kind === 'sticker') Object.assign(extra, { animated: checkSticker(file.buffer).animated });
  if (kind === 'voice') {
    // Voice note WhatsApp: OGG/Opus mono. WebM (Chrome/Edge) di-remux; MP4/AAC (Safari) dikirim sebagai audio biasa.
    let info = null;
    if (file.mimetype.endsWith('/webm')) {
      try { info = webmToOgg(file.buffer); } catch (e) { throw e instanceof HttpError ? e : new HttpError(400, 'Rekaman tidak dapat dikonversi: ' + e.message); }
      Object.assign(file, { buffer: info.buffer, size: info.buffer.length, mimetype: 'audio/ogg', originalname: 'voice.ogg' });
    } else if (file.mimetype === 'audio/ogg') {
      info = oggOpusInfo(file.buffer);
      if (!info) throw new HttpError(400, 'Rekaman OGG harus memakai codec Opus.');
      file.originalname = 'voice.ogg';
    } else { file.mimetype = 'audio/mp4'; file.originalname = 'voice.m4a'; }
    Object.assign(extra, { voice: !!info && info.channels === 1, duration: info ? Math.round(info.duration * 10) / 10 : Number(req.body.duration) || 0 });
  }
  const id = await uploadMedia(file);
  cacheMedia(id, file.buffer, { mime: file.mimetype, size: file.size, filename: file.originalname });
  res.json({ id, mime: file.mimetype, filename: file.originalname, size: file.size, ...extra });
}));
// Proxy media (token tetap di server). Hak akses mengikuti percakapan/grup pemilik media.
function mediaOwnerOr404(req) {
  if (!/^\d+$/.test(req.params.id)) throw new HttpError(400, 'ID media tidak valid.');
  const owner = db.messages.find((m) => m.content?.mediaId === req.params.id);
  if (!owner) throw new HttpError(404, 'Media tidak ditemukan.');
  if (owner.groupId) { if (req.user.role !== 'admin') throw new HttpError(404, 'Media tidak ditemukan.'); }
  else {
    const conv = byId('conversations', owner.conversationId);
    if (!conv || !canSeeConv(req.user, conv)) throw new HttpError(404, 'Media tidak ditemukan.');
  }
  return owner;
}
// Unduh dari Meta ke cache lokal (URL media Meta hanya berlaku ±5 menit, jadi selalu diminta ulang)
async function fetchMediaToCache(id, filename) {
  const hit = cachedMedia(id);
  if (hit) return hit;
  const info = await graph('get', id);
  if (Number(info.file_size) > 100 * 1024 * 1024) throw new HttpError(400, 'Media lebih dari 100 MB.');
  const tmp = mediaCacheFile(id) + '.' + uid() + '.tmp';
  try {
    const r = await axios.get(info.url, { responseType: 'stream', headers: { Authorization: `Bearer ${meta().accessToken}` }, timeout: 120000 });
    await new Promise((ok, no) => { const w = fs.createWriteStream(tmp); r.data.pipe(w); w.on('finish', ok); w.on('error', no); r.data.on('error', no); });
  } catch (e) { fs.rmSync(tmp, { force: true }); throw e.response ? metaError(e) : new HttpError(502, 'Gagal mengunduh media dari Meta: ' + e.message); }
  fs.renameSync(tmp, mediaCacheFile(id));
  const m = { mime: info.mime_type || 'application/octet-stream', size: Number(info.file_size) || fs.statSync(mediaCacheFile(id)).size, filename: filename || '' };
  fs.writeFileSync(mediaCacheFile(id) + '.json', JSON.stringify(m));
  return { file: mediaCacheFile(id), ...m };
}
app.get('/api/media/:id', wrap(async (req, res) => {
  const owner = mediaOwnerOr404(req);
  const c = await fetchMediaToCache(req.params.id, owner.content.filename);
  res.type(c.mime);
  if (req.query.download) res.attachment(owner.content.filename || c.filename || `media-${req.params.id}`);
  res.sendFile(c.file, { headers: { 'Cache-Control': 'private, max-age=86400' } }); // sendFile mendukung Range (seek audio/video)
}));
app.get('/api/media/:id/info', wrap(async (req, res) => {
  mediaOwnerOr404(req);
  const c = cachedMedia(req.params.id);
  if (c) return res.json({ mime: c.mime, size: c.size });
  const info = await graph('get', req.params.id);
  res.json({ mime: info.mime_type || '', size: Number(info.file_size) || 0 });
}));

/* Pustaka stiker */
app.get('/api/stickers', (req, res) => {
  res.json((db.stickers || []).slice().sort((a, b) => b.lastUsedAt - a.lastUsedAt).map((s) => ({ id: s.id, animated: s.animated, size: s.size })));
});
app.get('/api/stickers/:id', (req, res) => {
  const s = stickerOr404(req.params.id);
  res.set('Cache-Control', 'private, max-age=604800').type('image/webp').sendFile(stickerFile(s.id));
});
app.post('/api/stickers', upload.single('file'), wrap(async (req, res) => {
  let buf;
  if (req.file) buf = req.file.buffer;
  else if (req.body.fromMediaId) { // simpan stiker yang diterima ke pustaka
    req.params.id = String(req.body.fromMediaId);
    const owner = mediaOwnerOr404(req);
    if (owner.type !== 'sticker') throw new HttpError(400, 'Pesan ini bukan stiker.');
    buf = fs.readFileSync((await fetchMediaToCache(req.params.id)).file);
  } else throw new HttpError(400, 'Pilih file stiker.');
  const s = addSticker(buf, req.user.name);
  audit(req, 'sticker.add', s.id);
  res.json({ id: s.id, animated: s.animated, size: s.size });
}));
app.delete('/api/stickers/:id', requireAdmin, wrap(async (req, res) => {
  const s = stickerOr404(req.params.id);
  db.stickers = db.stickers.filter((x) => x.id !== s.id); fs.rmSync(stickerFile(s.id), { force: true });
  audit(req, 'sticker.delete', s.id); save();
  res.json({ ok: true });
}));

app.post('/api/conversations/:id/messages', wrap(async (req, res) => {
  const conv = convOr404(req);
  const contact = byId('contacts', conv.contactId);
  const type = str(req.body.type, 40);
  if (type === 'flow' && req.body.mode === 'draft' && req.user.role !== 'admin') throw new HttpError(403, 'Hanya admin yang dapat mengirim flow dalam mode draft.');
  if (type === 'template') {
    const tpl = findTemplate(str(req.body.name, 512), str(req.body.language, 15));
    if (!tpl) throw new HttpError(400, 'Template tidak ditemukan. Sinkronkan template terlebih dahulu.');
    if (tpl.status !== 'APPROVED') throw new HttpError(400, `Template berstatus ${tpl.status}, hanya APPROVED yang dapat dikirim.`);
    const msg = await sendTemplateTo(contact, tpl, req.body.values || {}, { userId: req.user.id, userName: req.user.name });
    if (!conv.assignedTo && req.user.role !== 'admin') { conv.assignedTo = req.user.id; save(); }
    audit(req, 'message.send', `template ${tpl.name} → ${contact.phone}`);
    return res.json(msg);
  }
  // Aturan jendela layanan 24 jam: pesan bebas hanya bila pelanggan mengirim pesan dalam 24 jam terakhir
  if (!windowOpen(conv)) throw new HttpError(400, 'Jendela layanan 24 jam sudah tertutup. Kirim pesan template yang disetujui untuk membuka kembali percakapan.');
  if (type === 'reaction') {
    // Reaksi ditempelkan ke pesan target (bukan gelembung baru). Emoji kosong = hapus reaksi.
    const target = byId('messages', str(req.body.messageId, 40));
    if (!target || target.conversationId !== conv.id || !target.wamid) throw new HttpError(400, 'Pesan ini tidak dapat diberi reaksi.');
    if (now() - target.timestamp > 30 * 86400000) throw new HttpError(400, 'Reaksi hanya dapat diberikan pada pesan yang berumur ≤ 30 hari.');
    const emoji = typeof req.body.emoji === 'string' ? req.body.emoji.trim().slice(0, 16) : '';
    if (emoji && !/\p{Extended_Pictographic}/u.test(emoji)) throw new HttpError(400, 'Reaksi harus berupa emoji.');
    await sendToMeta({ messaging_product: 'whatsapp', recipient_type: 'individual', to: contact.phone, type: 'reaction', reaction: { message_id: target.wamid, emoji } },
      { source: 'inbox', contact, conversation: conv, userId: req.user.id, userName: req.user.name });
    target.myReaction = emoji || null; save();
    emitConv(conv, 'message:update', { message: target });
    return res.json(target);
  }
  if (type === 'sticker' && req.body.stickerId) {
    const st = stickerOr404(req.body.stickerId);
    Object.assign(req.body, { mediaId: await ensureStickerMedia(st), animated: st.animated });
    st.lastUsedAt = now(); save();
  }
  const built = buildOutbound(type, req.body);
  const payload = { messaging_product: 'whatsapp', recipient_type: 'individual', to: contact.phone, type: built.type || type, ...built.payload };
  if (req.body.replyTo) { const ctx = byId('messages', req.body.replyTo); if (ctx?.wamid) payload.context = { message_id: ctx.wamid }; }
  const r = await sendToMeta(payload, { source: 'inbox', contact, conversation: conv, userId: req.user.id, userName: req.user.name });
  if (!conv.assignedTo && req.user.role !== 'admin') conv.assignedTo = req.user.id;
  const msg = addMessage(conv, { direction: 'out', type: built.type || type, content: built.content, wamid: r.messages?.[0]?.id, status: 'accepted', userId: req.user.id, userName: req.user.name, contextId: payload.context?.message_id || null });
  res.json(msg);
}));

/* Template */
app.get('/api/templates', (req, res) => res.json({ syncedAt: db.templatesSyncedAt, rows: db.templates }));
app.post('/api/templates/sync', wrap(async (req, res) => {
  const all = []; let after;
  do {
    const r = await graph('get', `${needWaba()}/message_templates`, { params: { fields: 'id,name,status,category,language,components,quality_score,rejected_reason,parameter_format', limit: 100, after } });
    all.push(...(r.data || []));
    after = r.paging?.next ? r.paging.cursors?.after : null;
  } while (after && all.length < 2000);
  db.templates = all; db.templatesSyncedAt = now(); save();
  res.json({ syncedAt: db.templatesSyncedAt, rows: db.templates });
}));
app.post('/api/templates', requireAdmin, wrap(async (req, res) => {
  const b = req.body;
  const name = str(b.name, 512);
  if (!/^[a-z0-9_]{1,512}$/.test(name)) throw new HttpError(400, 'Nama template hanya huruf kecil, angka, dan garis bawah.');
  if (!['MARKETING', 'UTILITY', 'AUTHENTICATION'].includes(b.category)) throw new HttpError(400, 'Kategori tidak valid.');
  const language = str(b.language, 15);
  if (!/^[a-z]{2,3}(_[A-Z]{2})?$/.test(language)) throw new HttpError(400, 'Kode bahasa tidak valid (contoh: id, en_US).');
  const bodyText = str(b.body, 1024);
  if (!bodyText) throw new HttpError(400, 'Isi (body) wajib diisi.');
  const splitEx = (s) => String(s || '').split('|').map((x) => x.trim()).filter(Boolean);
  const components = [];
  if (b.headerText) {
    const text = str(b.headerText, 60);
    const hv = templateVars(text);
    if (hv.length > 1) throw new HttpError(400, 'Header teks hanya boleh 1 variabel.');
    const h = { type: 'HEADER', format: 'TEXT', text };
    if (hv.length) { const ex = splitEx(b.headerExample); if (!ex.length) throw new HttpError(400, 'Contoh nilai variabel header wajib diisi.'); h.example = { header_text: ex.slice(0, 1) }; }
    components.push(h);
  }
  const bv = templateVars(bodyText);
  const body = { type: 'BODY', text: bodyText };
  if (bv.length) {
    if (!bv.every((v, i) => v === String(i + 1))) throw new HttpError(400, 'Variabel body harus berurutan: {{1}}, {{2}}, ...');
    const ex = splitEx(b.bodyExample);
    if (ex.length !== bv.length) throw new HttpError(400, `Isi ${bv.length} contoh nilai variabel body, dipisah "|".`);
    body.example = { body_text: [ex] };
  }
  components.push(body);
  if (b.footer) components.push({ type: 'FOOTER', text: str(b.footer, 60) });
  const buttons = (Array.isArray(b.buttons) ? b.buttons : []).slice(0, 10).map((x) => {
    const text = str(x.text, 25);
    if (!text) return null;
    if (x.type === 'URL') { if (!/^https?:\/\//.test(x.url || '')) throw new HttpError(400, 'URL tombol tidak valid.'); return { type: 'URL', text, url: str(x.url, 2000) }; }
    if (x.type === 'PHONE_NUMBER') { const p = normPhone(x.phone); if (!validPhone(p)) throw new HttpError(400, 'Nomor tombol telepon tidak valid.'); return { type: 'PHONE_NUMBER', text, phone_number: '+' + p }; }
    return { type: 'QUICK_REPLY', text };
  }).filter(Boolean);
  if (buttons.length) components.push({ type: 'BUTTONS', buttons });
  const r = await graph('post', `${needWaba()}/message_templates`, { data: { name, language, category: b.category, components } });
  db.templates.push({ id: r.id, name, language, category: r.category || b.category, status: r.status || 'PENDING', components });
  audit(req, 'template.create', `${name} (${language}) → ${r.status}`); save();
  res.json(r);
}));
app.delete('/api/templates/:name', requireAdmin, wrap(async (req, res) => {
  const name = str(req.params.name, 512);
  const params = { name };
  if (req.query.id) params.hsm_id = str(req.query.id, 40); // hapus satu bahasa saja
  await graph('delete', `${needWaba()}/message_templates`, { params });
  db.templates = db.templates.filter((t) => (params.hsm_id ? String(t.id) !== params.hsm_id : t.name !== name));
  audit(req, 'template.delete', name); save();
  res.json({ ok: true });
}));

/* Campaign (admin) */
function campaignSummary(c) {
  const counts = { queued: 0, sent: 0, delivered: 0, read: 0, failed: 0, skipped: 0 };
  c.recipients.forEach((r) => { const k = r.status === 'played' ? 'read' : r.status; counts[k] = (counts[k] || 0) + 1; });
  const { recipients, ...rest } = c;
  return { ...rest, total: recipients.length, counts };
}
app.get('/api/campaigns', requireAdmin, (req, res) => res.json(db.campaigns.slice().reverse().map(campaignSummary)));
app.get('/api/campaigns/:id', requireAdmin, wrap(async (req, res) => {
  const c = byId('campaigns', req.params.id);
  if (!c) throw new HttpError(404, 'Campaign tidak ditemukan.');
  res.json({ ...campaignSummary(c), recipients: c.recipients.slice(0, 1000).map((r) => ({ ...r, name: byId('contacts', r.contactId)?.name || '' })) });
}));
app.post('/api/campaigns', requireAdmin, wrap(async (req, res) => {
  const b = req.body;
  const name = str(b.name, 120);
  if (!name) throw new HttpError(400, 'Nama campaign wajib diisi.');
  const tpl = findTemplate(str(b.templateName, 512), str(b.language, 15));
  if (!tpl) throw new HttpError(400, 'Template tidak ditemukan.');
  if (tpl.status !== 'APPROVED') throw new HttpError(400, 'Hanya template APPROVED yang dapat dipakai campaign.');
  const labels = cleanLabels(b.labels);
  let targets = db.contacts.filter((c) => !labels.length || (c.labels || []).some((l) => labels.includes(l)));
  if (b.optInOnly !== false) targets = targets.filter((c) => c.optIn);
  if (!targets.length) throw new HttpError(400, 'Tidak ada kontak yang cocok dengan filter (periksa label & opt-in).');
  // Validasi variabel sekali dengan kontak pertama
  buildTemplateComponents(tpl, b.values || {}, targets[0]);
  const camp = {
    id: uid('p_'), name, templateName: tpl.name, language: tpl.language, values: b.values || {}, labels, optInOnly: b.optInOnly !== false,
    status: 'draft', createdAt: now(), createdBy: req.user.name,
    recipients: targets.map((c) => ({ contactId: c.id, phone: c.phone, status: 'queued', wamid: null, error: null })),
  };
  db.campaigns.push(camp); audit(req, 'campaign.create', `${name}: ${targets.length} penerima`); save();
  res.json(campaignSummary(camp));
}));
app.post('/api/campaigns/:id/:action(start|pause|cancel)', requireAdmin, wrap(async (req, res) => {
  const c = byId('campaigns', req.params.id);
  if (!c) throw new HttpError(404, 'Campaign tidak ditemukan.');
  const a = req.params.action;
  if (a === 'start') {
    if (!['draft', 'paused'].includes(c.status)) throw new HttpError(400, 'Campaign tidak dapat dimulai dari status ini.');
    needPhone(); if (!meta().accessToken) throw new HttpError(400, 'Koneksi Meta belum dikonfigurasi.');
    c.status = 'running'; c.startedAt = c.startedAt || now();
  } else if (a === 'pause') {
    if (c.status !== 'running') throw new HttpError(400, 'Campaign tidak sedang berjalan.');
    c.status = 'paused';
  } else {
    if (['done', 'cancelled'].includes(c.status)) throw new HttpError(400, 'Campaign sudah selesai.');
    c.status = 'cancelled'; c.finishedAt = now();
    c.recipients.forEach((r) => { if (r.status === 'queued') r.status = 'skipped'; });
  }
  audit(req, 'campaign.' + a, c.name); save();
  io?.to('admins').emit('campaign:update', campaignSummary(c));
  res.json(campaignSummary(c));
}));
app.get('/api/campaigns/:id/export.csv', requireAdmin, (req, res) => {
  const c = byId('campaigns', req.params.id);
  if (!c) return res.sendStatus(404);
  const lines = ['phone,name,status,wamid,error,sent_at', ...c.recipients.map((r) => [r.phone, byId('contacts', r.contactId)?.name || '', r.status, r.wamid, r.error, r.sentAt ? new Date(r.sentAt).toISOString() : ''].map(csvCell).join(','))];
  res.type('text/csv').attachment(`campaign-${c.id}.csv`).send('﻿' + lines.join('\n'));
});

/* Panggilan (WhatsApp Business Calling API) */
app.get('/api/calls/settings', wrap(async (req, res) => {
  const r = await graph('get', `${needPhone()}/settings`);
  res.json({ calling: r.calling || null });
}));
app.post('/api/calls/settings', requireAdmin, wrap(async (req, res) => {
  const calling = {};
  if (typeof req.body.enabled === 'boolean') calling.status = req.body.enabled ? 'ENABLED' : 'DISABLED';
  if (typeof req.body.callback === 'boolean') calling.callback_permission_status = req.body.callback ? 'ENABLED' : 'DISABLED';
  if (!Object.keys(calling).length) throw new HttpError(400, 'Tidak ada pengaturan yang diubah.');
  const r = await graph('post', `${needPhone()}/settings`, { data: { calling } });
  audit(req, 'calls.settings', JSON.stringify(calling));
  res.json(r);
}));
// Kontak yang memberi izin untuk ditelepon balik dan izinnya masih berlaku
app.get('/api/calls/callbacks', (req, res) => {
  const rows = db.contacts.filter((c) => callPermissionActive(c)).map((c) => {
    const conv = idx.convByContact.get(c.id);
    return { contactId: c.id, name: c.name || c.waName || '', phone: c.phone, avatarV: c.avatarV || 0, ...c.callPermission, conversationId: conv && canSeeConv(req.user, conv) ? conv.id : null };
  }).sort((a, b) => b.at - a.at);
  res.json(rows);
});
app.get('/api/calls', (req, res) => res.json(db.calls.slice(-200).reverse().map(publicCall)));
// Panggilan yang masih berdering (untuk perangkat yang baru tersambung ulang, mis. HP yang layarnya sempat mati)
app.get('/api/calls/ringing', (req, res) => {
  const c = db.calls.slice().reverse().find((x) => x.status === 'ringing' && x.offer && now() - x.startedAt < 90 * 1000);
  res.json(c ? { ...publicCall(c), offer: c.offer } : null);
});
app.post('/api/calls/outbound', wrap(async (req, res) => {
  const contact = byId('contacts', req.body.contactId);
  if (!contact) throw new HttpError(404, 'Kontak tidak ditemukan.');
  const conv = idx.convByContact.get(contact.id);
  if (conv && !canSeeConv(req.user, conv)) throw new HttpError(403, 'Kontak ini ditangani agen lain.');
  // Meta mewajibkan izin telepon dari pengguna; tolak lebih awal bila izin yang tercatat sudah tidak berlaku
  if (!callPermissionActive(contact)) throw new HttpError(400, 'Pelanggan ini belum memberi izin untuk ditelepon, atau izinnya sudah kedaluwarsa.');
  if (db.calls.some((c) => c.callerId === req.user.id && ['calling', 'ringing', 'accepted'].includes(c.status) && now() - c.startedAt < 2 * 3600 * 1000))
    throw new HttpError(409, 'Anda masih memiliki panggilan yang berlangsung.');
  const sdp = sdpParam(req.body.sdp);
  if (!sdp) throw new HttpError(400, 'SDP offer kosong.');
  const r = await graph('post', `${needPhone()}/calls`, { data: { messaging_product: 'whatsapp', to: contact.phone, action: 'connect', session: { sdp_type: 'offer', sdp } } });
  const callId = r.calls?.[0]?.id;
  if (!callId) throw new HttpError(502, 'Meta tidak mengembalikan ID panggilan.');
  const call = { id: uid('k_'), callId, contactId: contact.id, phone: contact.phone, direction: 'BUSINESS_INITIATED', status: 'calling', startedAt: now(), callerId: req.user.id, answeredBy: req.user.id, answeredName: req.user.name };
  db.calls.push(call);
  audit(req, 'call.outbound', contact.phone); save();
  io?.emit('call:update', publicCall(call));
  res.json(publicCall(call));
}));
app.post('/api/calls/:id/:action(accept|reject|terminate)', wrap(async (req, res) => {
  const call = byId('calls', req.params.id);
  if (!call) throw new HttpError(404, 'Panggilan tidak ditemukan.');
  const a = req.params.action;
  if (call.direction === 'BUSINESS_INITIATED' && a !== 'terminate') throw new HttpError(400, 'Panggilan keluar hanya dapat diakhiri.');
  if (call.direction === 'BUSINESS_INITIATED' && call.callerId !== req.user.id && req.user.role !== 'admin') throw new HttpError(403, 'Hanya penelepon yang dapat mengakhiri panggilan ini.');
  const base = { messaging_product: 'whatsapp', call_id: call.callId };
  if (a === 'accept') {
    if (call.status !== 'ringing') throw new HttpError(409, 'Panggilan sudah tidak berdering.');
    if (call.answeredBy && call.answeredBy !== req.user.id) throw new HttpError(409, 'Panggilan sudah diangkat agen lain.');
    const sdp = sdpParam(req.body.sdp);
    if (!sdp) throw new HttpError(400, 'SDP answer kosong.');
    call.answeredBy = req.user.id;
    const session = { sdp_type: 'answer', sdp };
    try {
      await graph('post', `${needPhone()}/calls`, { data: { ...base, action: 'pre_accept', session } });
      await graph('post', `${needPhone()}/calls`, { data: { ...base, action: 'accept', session } });
    } catch (e) { call.answeredBy = null; throw e; }
    call.status = 'accepted'; call.answeredAt = now(); call.answeredName = req.user.name;
  } else {
    await graph('post', `${needPhone()}/calls`, { data: { ...base, action: a } });
    call.status = a === 'reject' ? 'rejected' : 'completed'; call.endedAt = now();
  }
  delete call.offer;
  audit(req, 'call.' + a, call.phone); save();
  io?.emit('call:update', publicCall(call));
  res.json(publicCall(call));
}));

/* Error handler */
app.use('/api', (req, res, next) => next(new HttpError(404, 'Endpoint tidak ditemukan.')));
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) err = new HttpError(400, err.code === 'LIMIT_FILE_SIZE' ? 'File terlalu besar.' : err.message);
  if (err.type === 'entity.parse.failed') err = new HttpError(400, 'JSON tidak valid.');
  const status = err.status || 500;
  if (status >= 500 && !(err instanceof HttpError)) console.error(err);
  res.status(status).json({ error: status >= 500 && !(err instanceof HttpError) ? 'Terjadi kesalahan server.' : err.message });
});

/* ───────────────────────── 8. Campaign worker ───────────────────────── */
// Antrean persisten: status penerima tersimpan di DB, sehingga campaign 'running' berlanjut setelah restart.
let workerBusy = false;
setInterval(async () => {
  if (workerBusy) return;
  const camp = db.campaigns.find((c) => c.status === 'running');
  if (!camp) return;
  workerBusy = true;
  try {
    const tpl = findTemplate(camp.templateName, camp.language);
    if (!tpl || tpl.status !== 'APPROVED') {
      camp.status = 'paused'; camp.lastError = 'Template tidak lagi berstatus APPROVED.';
      io?.to('admins').emit('campaign:update', campaignSummary(camp)); save(); return;
    }
    const batch = camp.recipients.filter((r) => r.status === 'queued').slice(0, CAMPAIGN_RATE);
    for (const r of batch) {
      if (camp.status !== 'running') break;
      const contact = byId('contacts', r.contactId);
      if (!contact) { r.status = 'skipped'; r.error = 'Kontak dihapus'; continue; }
      try {
        const msg = await sendTemplateTo(contact, tpl, camp.values, { campaignId: camp.id, userName: 'Campaign: ' + camp.name }, { source: 'campaign', campaign: camp });
        r.status = 'sent'; r.wamid = msg.wamid; r.sentAt = now();
      } catch (e) {
        r.status = 'failed'; r.error = e.message;
        // Error token/izin/rate limit: hentikan sementara agar tidak membakar seluruh antrean
        const code = e.meta?.code;
        if ([190, 200, 10, 4, 80007, 130429, 131056].includes(code) || e.status === 400 && /belum dikonfigurasi/.test(e.message)) {
          if ([130429, 80007, 4].includes(code)) { r.status = 'queued'; r.error = null; }
          camp.status = 'paused'; camp.lastError = e.message; break;
        }
      }
    }
    if (camp.status === 'running' && !camp.recipients.some((r) => r.status === 'queued')) { camp.status = 'done'; camp.finishedAt = now(); }
    save();
    io?.to('admins').emit('campaign:update', campaignSummary(camp));
  } finally { workerBusy = false; }
}, 1000);

/* ───────────────────────── 9. Socket.IO & start ───────────────────────── */

const server = http.createServer(app);
const io = new Server(server, { serveClient: true, cors: { origin: false } });
io.use((socket, next) => {
  const user = userFromToken(parseCookies(socket.handshake.headers.cookie)[COOKIE_NAME]);
  if (!user) return next(new Error('unauthorized'));
  socket.data.user = user; next();
});
// Status "sedang mengetik": diteruskan ke CS lain + typing indicator resmi WhatsApp ke pelanggan.
// Meta menampilkan indikator maks. 25 detik (atau sampai balasan terkirim), jadi dikirim paling sering tiap 20 detik per percakapan.
// Catatan: Cloud API tidak mengirim webhook saat pelanggan mengetik, jadi arah sebaliknya tidak tersedia.
const typingSentAt = new Map();
function sendCustomerTyping(conv) {
  if (!windowOpen(conv) || now() - (typingSentAt.get(conv.id) || 0) < 20000) return;
  const last = db.messages.filter((m) => m.conversationId === conv.id && m.direction === 'in' && m.wamid).pop();
  if (!last || now() - last.timestamp > SERVICE_WINDOW_MS) return;
  typingSentAt.set(conv.id, now());
  graph('post', `${needPhone()}/messages`, { data: { messaging_product: 'whatsapp', status: 'read', message_id: last.wamid, typing_indicator: { type: 'text' } } })
    .catch((e) => { typingSentAt.delete(conv.id); console.warn('[typing]', e.message); });
}
io.on('connection', (socket) => {
  const u = socket.data.user;
  socket.join('user:' + u.id);
  socket.join(u.role === 'admin' ? 'admins' : 'agents');
  socket.on('typing', (payload) => {
    const user = byId('users', u.id);
    const conv = byId('conversations', String(payload?.conversationId || ''));
    if (!user?.active || !conv || !canSeeConv(user, conv)) return;
    const evt = { conversationId: conv.id, userId: user.id, name: user.name, at: now() };
    socket.to(['admins', conv.assignedTo ? 'user:' + conv.assignedTo : 'agents']).emit('typing', evt);
    if (payload.toCustomer !== false) { try { sendCustomerTyping(conv); } catch (e) { /* Meta belum dikonfigurasi */ } }
  });
});

function shutdown() { try { flushDb(); } finally { process.exit(0); } }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

server.listen(PORT, () => console.log(`[kontaq] berjalan di http://localhost:${PORT}`));

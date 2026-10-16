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
  flows: [], flowRuns: [],
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
    case 'audio': return '🎵 Audio';
    case 'document': return '📄 ' + (c.filename || 'Dokumen');
    case 'sticker': return 'Stiker';
    case 'location': return '📍 ' + (c.name || 'Lokasi');
    case 'interactive': return '☰ ' + (c.body || 'Pesan interaktif');
    case 'interactive_reply': return '↩ ' + c.title;
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
      p[type] = obj;
      return { payload: p, content: { mediaId: obj.id, caption: obj.caption || '', filename: obj.filename || '', mime: str(b.mime, 100) } };
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
  return comps;
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
    content: { name: tpl.name, language: tpl.language, body: renderTemplateText(tpl, components) }, ...extra,
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
  return { button: 'buttons', list: 'list', call_permission_request: 'call_permission' }[p.interactive?.type] || 'interactive';
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
    return { type: t, content: { mediaId: o.id, mime: o.mime_type, caption: o.caption || '', filename: o.filename || '', voice: !!o.voice } };
  }
  switch (t) {
    case 'text': return { type: 'text', content: { body: m.text?.body || '' } };
    case 'location': return { type: 'location', content: m.location || {} };
    case 'interactive': {
      if (m.interactive?.type === 'call_permission_reply') {
        const p = m.interactive.call_permission_reply || {};
        return { type: 'call_permission', content: { response: p.response === 'accept' ? 'accept' : 'reject', permanent: !!p.is_permanent, expiresAt: p.expiration_timestamp ? Number(p.expiration_timestamp) * 1000 : 0, source: p.response_source || '' } };
      }
      const r = m.interactive?.button_reply || m.interactive?.list_reply || m.interactive?.nfm_reply || {};
      return { type: 'interactive_reply', content: { id: r.id || '', title: r.title || r.name || 'Balasan', description: r.description || '' } };
    }
    case 'button': return { type: 'button', content: { text: m.button?.text || '', payload: m.button?.payload || '' } };
    case 'contacts': return { type: 'contacts', content: { contacts: (m.contacts || []).map((c) => ({ name: c.name?.formatted_name, phones: (c.phones || []).map((p) => p.phone) })) } };
    default: return { type: 'unsupported', content: { body: `[Pesan tipe "${t}" tidak didukung]` } };
  }
}

function handleMessages(value) {
  const profiles = Object.fromEntries((value.contacts || []).map((c) => [c.wa_id, c.profile?.name]));
  for (const m of value.messages || []) {
    if (idx.wamid.has(m.id)) continue; // dedup retry Meta
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
    const prevInboundAt = conv.lastInboundAt || 0;
    const msg = addMessage(conv, { direction: 'in', type, content, wamid: m.id, timestamp: Number(m.timestamp) * 1000 || now(), contextId: m.context?.id || null });
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
const FLOW_MAX_AUTO_PER_HOUR = 10;
const FLOW_RUNS_MAX = 3000;
const FLOW_STEP_LABEL = { trigger: 'Pemicu', condition: 'Kondisi', send: 'Kirim pesan', assign: 'Teruskan ke agen', label: 'Label kontak', status: 'Ubah status', note: 'Catatan internal', delay: 'Tunggu' };
const FLOW_COND_LABEL = { keyword: 'Kata kunci', schedule: 'Jadwal', business_hours: 'Jam kerja', label: 'Label kontak', new_contact: 'Kontak baru', message_type: 'Jenis pesan', assigned: 'Sudah ditugaskan' };
const FLOW_MSG_TYPES = ['text', 'image', 'video', 'audio', 'document', 'sticker', 'location', 'reply', 'contacts'];
const STATUS_LABEL = { open: 'Terbuka', pending: 'Menunggu', closed: 'Selesai' };

const inTimeRange = (time, open, close) => (close > open ? time >= open && time < close : time >= open || time < close);
const zonedDate = (tz, at = now()) => new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(at));
const flowTz = () => arCfg().timezone;

function cleanFlowNode(raw, isRoot) {
  const type = String(raw?.type || '');
  if (!FLOW_STEP_LABEL[type]) throw new HttpError(400, `Jenis langkah tidak dikenal: "${type}".`);
  if (isRoot !== (type === 'trigger')) throw new HttpError(400, 'Pemicu hanya boleh ada satu, di awal flow.');
  const c = raw.cfg || {}, name = `Langkah "${FLOW_STEP_LABEL[type]}"`;
  const time = (v) => { if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(v || '')) throw new HttpError(400, `${name}: jam tidak valid (format HH:MM).`); return v; };
  const num = (v, min, max, label) => { const n = Number(v); if (!Number.isInteger(n) || n < min || n > max) throw new HttpError(400, `${name}: ${label} harus bilangan bulat ${min}–${max}.`); return n; };
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
      }
      break;
    }
    case 'send': cfg = cleanReplyExtras(c, name, true); break;
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
    if (n.type === 'condition') { n.yes = visit(src[id].yes); n.no = visit(src[id].no); }
    else n.next = visit(src[id].next);
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

// Satu langkah. dry = simulasi (tanpa efek samping). Mengembalikan { next, log, ok, action, wait, preview }
async function execFlowNode(flow, n, ctx, dry) {
  const c = n.cfg;
  switch (n.type) {
    case 'trigger': return { next: n.next, log: 'Pesan masuk dari pelanggan' };
    case 'condition': {
      const yes = evalFlowCond(c, ctx);
      return { next: yes ? n.yes : n.no, log: `${FLOW_COND_LABEL[c.kind]}: ${yes ? 'Ya' : 'Tidak'}`, branch: yes ? 'yes' : 'no' };
    }
    case 'send': {
      const preview = { text: fillVars(c.text, ctx.contact), image: c.image, buttons: c.buttons };
      if (!windowOpen(ctx.conv)) return { next: n.next, ok: false, log: 'Tidak dikirim: di luar jendela layanan 24 jam.' };
      if (dry) return { next: n.next, action: true, log: 'Mengirim pesan', preview };
      if (recentAutoCount(ctx.conv, now() - 3600000) >= FLOW_MAX_AUTO_PER_HOUR) return { next: n.next, ok: false, log: `Tidak dikirim: batas ${FLOW_MAX_AUTO_PER_HOUR} pesan otomatis per jam untuk percakapan ini tercapai.` };
      try {
        await sendAutoContent(ctx.conv, ctx.contact, c, { auto: 'flow', userName: 'Flow: ' + flow.name, source: 'flow', btnPrefix: `fl_${n.id}`, contextId: ctx.contextId, flowId: flow.id });
        ctx.contextId = null; // hanya pesan pertama yang mengutip pesan pelanggan
        return { next: n.next, action: true, log: 'Pesan terkirim ke Meta' };
      } catch (e) { return { next: n.next, ok: false, log: 'Gagal mengirim: ' + e.message }; }
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
      if (!dry) emitConv(ctx.conv, 'conversation:update', serializeConv(ctx.conv));
      return { next: n.next, action: true, log: `Status → ${STATUS_LABEL[c.status]}` };
    }
    case 'note': {
      const text = fillVars(c.text, ctx.contact);
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

// Jalankan dari langkah startId sampai selesai atau bertemu "Tunggu" (dry: "Tunggu" dilewati dan hanya dicatat)
async function execFlow(flow, run, ctx, startId, dry) {
  run.status = 'running';
  let id = startId, guard = 0;
  while (id && guard++ <= FLOW_MAX_NODES) {
    const n = flow.nodes[id];
    if (!n) break;
    const r = await execFlowNode(flow, n, ctx, dry);
    run.steps.push({ nodeId: id, type: n.type, at: now(), ok: r.ok !== false, log: r.log, ...(r.preview ? { preview: r.preview } : {}), ...(r.branch ? { branch: r.branch } : {}) });
    if (r.action) run.actions++;
    if (r.ok === false) run.error = r.log;
    if (r.wait && !dry) {
      Object.assign(run, { status: 'waiting', resumeAt: now() + r.wait, resumeNode: r.next, waitSince: now(), cancelOnReply: n.cfg.cancelOnReply });
      return run;
    }
    id = r.next;
  }
  run.status = run.error && !run.actions ? 'failed' : 'done';
  run.finishedAt = now();
  return run;
}

function pushFlowRun(run) {
  db.flowRuns.push(run);
  if (db.flowRuns.length > FLOW_RUNS_MAX) {
    const drop = db.flowRuns.length - FLOW_RUNS_MAX;
    let removed = 0;
    db.flowRuns = db.flowRuns.filter((r) => (removed < drop && r.status !== 'waiting' ? (removed++, false) : true));
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
  if (db.flowRuns.some((r) => r.status === 'waiting' && r.flowId === flow.id && r.conversationId === conv.id)) return 'Flow masih menunggu (langkah Tunggu) di percakapan ini.';
  return null;
}
function cancelFlowRuns(pred, reason) {
  let n = 0;
  for (const r of db.flowRuns) if (r.status === 'waiting' && pred(r)) { r.status = 'cancelled'; r.error = reason; r.finishedAt = now(); n++; }
  if (n) save();
  return n;
}

async function runFlows(conv, contact, msg, prevInboundAt) {
  const flows = db.flows.filter((f) => f.enabled).sort((a, b) => a.order - b.order);
  // Pesan baru dari pelanggan membatalkan langkah "Tunggu" yang diatur batal bila dibalas
  cancelFlowRuns((r) => r.conversationId === conv.id && r.cancelOnReply, 'Pelanggan mengirim pesan baru.');
  if (!flows.length) return false;
  const at = now(), text = inboundText(msg);
  for (const flow of flows) {
    if (flowGate(flow, conv, at)) continue;
    const ctx = { conv, contact, text, msgType: msg.type, prevInboundAt, at, clock: zonedNow(flowTz(), at), contextId: msg.wamid };
    const run = { id: uid('fr_'), flowId: flow.id, flowName: flow.name, conversationId: conv.id, contactId: contact.id, phone: contact.phone,
      text: text.slice(0, 300), msgType: msg.type, prevInboundAt, startedAt: at, status: 'running', steps: [], actions: 0, error: null };
    // Tandai sebelum aksi asinkron agar pesan beruntun tidak menjalankan flow (ber-jeda) dua kali
    const prevLog = conv.flowLog?.[flow.id];
    conv.flowLog = { ...conv.flowLog, [flow.id]: at };
    await execFlow(flow, run, ctx, flow.root, false);
    if (!run.actions && run.status !== 'waiting') {
      if (prevLog) conv.flowLog[flow.id] = prevLog; else delete conv.flowLog[flow.id];
      if (!run.error) continue; // tidak ada cabang yang cocok: coba flow berikutnya tanpa mencatat
    }
    pushFlowRun(run); finishFlowRun(flow, run);
    if (run.actions || run.status === 'waiting') return true;
  }
  return false;
}

// Worker: lanjutkan langkah "Tunggu" yang sudah jatuh tempo
let flowWorkerBusy = false;
setInterval(async () => {
  if (flowWorkerBusy) return;
  const due = db.flowRuns.filter((r) => r.status === 'waiting' && r.resumeAt <= now());
  if (!due.length) return;
  flowWorkerBusy = true;
  try {
    for (const run of due) {
      const flow = byId('flows', run.flowId), conv = byId('conversations', run.conversationId), contact = byId('contacts', run.contactId);
      const stop = (reason) => { run.status = 'cancelled'; run.error = reason; run.finishedAt = now(); save(); };
      if (!flow || !flow.enabled) { stop('Flow dinonaktifkan atau dihapus.'); continue; }
      if (!conv || !contact) { stop('Percakapan atau kontak sudah dihapus.'); continue; }
      if (run.cancelOnReply && lastHumanReplyAt(conv) > run.waitSince) { stop('CS sudah membalas.'); continue; }
      const ctx = { conv, contact, text: run.text, msgType: run.msgType, prevInboundAt: run.prevInboundAt, at: run.startedAt, clock: zonedNow(flowTz()), contextId: null };
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
  const ctx = { conv, contact, text: str(b.text, 1000), msgType, prevInboundAt: b.newContact ? 0 : at - 3600000, at, clock: { day, time }, contextId: null };
  const run = { steps: [], actions: 0, error: null };
  await execFlow({ ...flow, rr: flow.rr || 0 }, run, ctx, flow.root, true);
  return { steps: run.steps, actions: run.actions, clock: { day, time } };
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
};

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
  waiting: db.flowRuns.filter((r) => r.flowId === f.id && r.status === 'waiting').length,
});
const flowOr404 = (id) => { const f = byId('flows', id); if (!f) throw new HttpError(404, 'Flow tidak ditemukan.'); return f; };
const recentRuns = (pred, n) => db.flowRuns.filter(pred).slice(-n).reverse();
app.get('/api/flows', requireAdmin, (req, res) => {
  const z = zonedNow(flowTz());
  res.json({
    flows: db.flows.slice().sort((a, b) => a.order - b.order).map(flowSummary),
    runs: recentRuns(() => true, 30), timezone: flowTz(), now: z, labels: contactLabels(),
    autoReplyEnabled: !!arCfg().enabled, hours: arCfg().away.hours,
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
  cancelFlowRuns((r) => r.flowId === f.id && r.resumeNode && !f.nodes[r.resumeNode], 'Langkah dihapus saat flow diubah.');
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
const LOG_SOURCES = { inbox: 'Dashboard', campaign: 'Campaign', auto_reply: 'Auto reply', flow: 'Flow otomatis', external: 'Di luar Kontaq' };
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
  if (b.status !== undefined) {
    if (!['open', 'pending', 'closed'].includes(b.status)) throw new HttpError(400, 'Status tidak valid.');
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
  if (rule.mimes && !rule.mimes.includes(req.file.mimetype)) throw new HttpError(400, `Format ${req.file.mimetype} tidak didukung untuk ${kind}. Didukung: ${rule.mimes.join(', ')}`);
  if (req.file.size > rule.max * 1024 * 1024) throw new HttpError(400, `Ukuran maksimal ${kind}: ${rule.max} MB.`);
  const id = await uploadMedia(req.file);
  res.json({ id, mime: req.file.mimetype, filename: req.file.originalname, size: req.file.size });
}));
// Proxy media: token tetap di server
app.get('/api/media/:id', wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) throw new HttpError(400, 'ID media tidak valid.');
  const owner = db.messages.find((m) => m.content?.mediaId === req.params.id);
  if (!owner) throw new HttpError(404, 'Media tidak ditemukan.');
  const conv = byId('conversations', owner.conversationId);
  if (!conv || !canSeeConv(req.user, conv)) throw new HttpError(404, 'Media tidak ditemukan.');
  const info = await graph('get', req.params.id);
  try {
    const r = await axios.get(info.url, { responseType: 'stream', headers: { Authorization: `Bearer ${meta().accessToken}` }, timeout: 60000 });
    res.set('Content-Type', info.mime_type || r.headers['content-type'] || 'application/octet-stream');
    res.set('Cache-Control', 'private, max-age=3600');
    if (req.query.download) res.attachment(owner.content.filename || `media-${req.params.id}`);
    r.data.pipe(res);
  } catch (e) { throw metaError(e); }
}));

app.post('/api/conversations/:id/messages', wrap(async (req, res) => {
  const conv = convOr404(req);
  const contact = byId('contacts', conv.contactId);
  const type = str(req.body.type, 40);
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

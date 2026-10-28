// =====================================================================
//  Cloudflare DNS Manager — Telegram Bot (Single File, Durable Object)
//
//  Deploy via wrangler / dashboard (lihat README.md).
//
//  Environment / Secret yang dibutuhkan:
//    BOT_TOKEN       = token bot dari @BotFather
//    WEBHOOK_SECRET  = string acak panjang untuk verifikasi webhook
//    ENCRYPTION_KEY  = 32 byte acak dalam base64 (untuk enkripsi API token CF)
//
//  Storage: Durable Object class "UserBot", binding name "USERBOT".
//  Tidak ada KV namespace.
// =====================================================================

/* ============================ KONFIGURASI ============================ */
const CF_API = 'https://api.cloudflare.com/client/v4';
const TG_API = 'https://api.telegram.org';
const STATE_TTL = 60 * 60 * 24 * 7;
// =====================================================================

/* ---------------------------- tipe record ---------------------------- */
const STRUCT = {
  MX: [['priority', 'Priority', 'int', 0, 65535]],
  URI: [
    ['priority', 'Priority', 'int', 0, 65535],
    ['weight', 'Weight', 'int', 0, 65535],
    ['target', 'Target (URI)', 'str', 1, 2048],
  ],
  SRV: [
    ['priority', 'Priority', 'int', 0, 65535],
    ['weight', 'Weight', 'int', 0, 65535],
    ['port', 'Port', 'int', 0, 65535],
    ['target', 'Target host', 'str', 1, 255],
  ],
  CAA: [
    ['flags', 'Flags', 'int', 0, 255],
    ['tag', 'Tag (issue/issuewild/iodef)', 'enum', 0, 0, ['issue', 'issuewild', 'iodef']],
    ['value', 'Value', 'str', 1, 2048],
  ],
  DS: [
    ['key_tag', 'Key tag', 'int', 0, 65535],
    ['algorithm', 'Algorithm', 'int', 0, 255],
    ['digest_type', 'Digest type', 'int', 0, 255],
    ['digest', 'Digest (hex)', 'hex', 1, 512],
  ],
  DNSKEY: [
    ['flags', 'Flags', 'int', 0, 65535],
    ['protocol', 'Protocol', 'int', 0, 255],
    ['algorithm', 'Algorithm', 'int', 0, 255],
    ['public_key', 'Public key (base64)', 'b64', 1, 4096],
  ],
  CERT: [
    ['type', 'Certificate type', 'int', 0, 65535],
    ['key_tag', 'Key tag', 'int', 0, 65535],
    ['algorithm', 'Algorithm', 'int', 0, 255],
    ['certificate', 'Certificate (base64)', 'b64', 1, 8192],
  ],
  TLSA: [
    ['usage', 'Usage', 'int', 0, 255],
    ['selector', 'Selector', 'int', 0, 255],
    ['matching_type', 'Matching type', 'int', 0, 255],
    ['certificate', 'Certificate association (hex)', 'hex', 1, 8192],
  ],
  SMIMEA: [
    ['usage', 'Usage', 'int', 0, 255],
    ['selector', 'Selector', 'int', 0, 255],
    ['matching_type', 'Matching type', 'int', 0, 255],
    ['certificate', 'Certificate association (hex)', 'hex', 1, 8192],
  ],
  SSHFP: [
    ['algorithm', 'Algorithm', 'int', 0, 255],
    ['type', 'Fingerprint type', 'int', 0, 255],
    ['fingerprint', 'Fingerprint (hex)', 'hex', 1, 512],
  ],
  LOC: [['content', 'Content (format LOC)', 'str', 1, 255]],
};

const TYPE_INFO = {
  A: [1, 1], AAAA: [1, 1], CNAME: [1, 1],
  TXT: [1, 0], NS: [1, 0], PTR: [1, 0], NAPTR: [1, 0],
  MX: [1, 0], SRV: [1, 0], URI: [1, 0], CAA: [1, 0], LOC: [1, 0],
  DS: [1, 0], DNSKEY: [1, 0], CERT: [1, 0], TLSA: [1, 0],
  SMIMEA: [1, 0], SSHFP: [1, 0],
  HTTPS: [1, 0], SVCB: [1, 0], OPENPGPKEY: [1, 0],
};
const TYPES = Object.keys(TYPE_INFO);
const BASIC = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS', 'SRV', 'CAA'];
const ADVANCED = TYPES.filter((t) => !BASIC.includes(t));

const FIXED_FIELDS = {
  A: [['content', 'IPv4', 'ipv4']],
  AAAA: [['content', 'IPv6', 'ipv6']],
  CNAME: [['content', 'Target hostname', 'host']],
  NS: [['content', 'Nameserver', 'host']],
  PTR: [['content', 'Target hostname', 'host']],
  HTTPS: [['content', 'Value (SvcParams)', 'str']],
  SVCB: [['content', 'Value (SvcParams)', 'str']],
  NAPTR: [['content', 'Value', 'str']],
  OPENPGPKEY: [['content', 'Public key (base64)', 'b64']],
  TXT: [['content', 'Isi TXT', 'str', 1, 4096]],
};

const TTL_CHOICES = [
  ['Auto', '1'], ['60', '60'], ['300', '300'], ['600', '600'],
  ['1800', '1800'], ['3600', '3600'], ['7200', '7200'],
  ['14400', '14400'], ['43200', '43200'], ['86400', '86400'],
];

/* ------------------------------ util ------------------------------- */
const enc = new TextEncoder();
const short = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
const isInt = (v, a, b) => /^\d+$/.test(v) && +v >= a && +v <= b;

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(bytes) {
  let s = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s);
}
async function aesKey(secret) {
  const raw = b64ToBytes(secret);
  if (raw.length !== 32) throw new Error('ENCRYPTION_KEY harus 32 byte base64');
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function encryptToken(secret, plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(secret), enc.encode(plain));
  return `v1.${bytesToB64(iv)}.${bytesToB64(ct)}`;
}
async function decryptToken(secret, blob) {
  const [v, iv, ct] = String(blob).split('.');
  if (v !== 'v1') throw new Error('format token tidak dikenal');
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(iv) }, await aesKey(secret), b64ToBytes(ct));
  return new TextDecoder().decode(pt);
}

/* --------------------------- Cloudflare ---------------------------- */
class CfError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

class Cloudflare {
  constructor(token, fetchImpl = fetch) { this.token = token; this.fetch = fetchImpl; }
  async _req(method, path, body) {
    const res = await this.fetch(`${CF_API}${path}`, {
      method,
      headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let json = null;
    try { json = await res.json(); } catch { /* ignore */ }
    if (!res.ok || !json || json.success === false) {
      const e = (json && json.errors && json.errors[0]) || {};
      const msg = [e.code, e.message].filter(Boolean).join(' ') || `HTTP ${res.status}`;
      throw new CfError(msg, res.status);
    }
    return json;
  }
  async _all(path) {
    const out = [];
    for (let page = 1; page <= 50; page++) {
      const sep = path.includes('?') ? '&' : '?';
      const j = await this._req('GET', `${path}${sep}page=${page}&per_page=50`);
      out.push(...(j.result || []));
      const total = j.result_info && j.result_info.total_pages;
      if (!total || page >= total) break;
    }
    return out;
  }
  zones() { return this._all('/zones'); }
  records(zoneId) { return this._all(`/zones/${zoneId}/dns_records`); }
  record(zoneId, rid) { return this._req('GET', `/zones/${zoneId}/dns_records/${rid}`).then((j) => j.result); }
  create(zoneId, payload) { return this._req('POST', `/zones/${zoneId}/dns_records`, payload).then((j) => j.result); }
  update(zoneId, rid, payload) { return this._req('PATCH', `/zones/${zoneId}/dns_records/${rid}`, payload).then((j) => j.result); }
  remove(zoneId, rid) { return this._req('DELETE', `/zones/${zoneId}/dns_records/${rid}`); }
}

/* ---------------------------- validasi ----------------------------- */
function fqdn(name, zoneName) {
  let n = String(name || '').trim().toLowerCase();
  if (n === '' || n === '@') return zoneName;
  if (n.endsWith('.')) n = n.slice(0, -1);
  if (n === zoneName) return n;
  if (n.endsWith('.' + zoneName)) return n;
  return `${n}.${zoneName}`;
}

function checkValue(kind, v, min = 1, max = 4096) {
  const s = String(v ?? '');
  if (s.length < min || s.length > max) return `panjang harus ${min}-${max}`;
  switch (kind) {
    case 'ipv4': {
      const p = s.split('.');
      if (p.length !== 4 || p.some((x) => !isInt(x, 0, 255))) return 'IPv4 tidak valid';
      return null;
    }
    case 'ipv6':
      if (!/^[0-9a-fA-F:]+$/.test(s) || (s.match(/::/g) || []).length > 1) return 'IPv6 tidak valid';
      return null;
    case 'host':
      if (!/^[a-z0-9_*]([a-z0-9_.*-]*[a-z0-9])?$/i.test(s)) return 'hostname tidak valid';
      return null;
    case 'hex':
      if (!/^[0-9a-fA-F]+$/.test(s) || s.length % 2) return 'harus hex genap';
      return null;
    case 'b64':
      if (!/^[A-Za-z0-9+/=\s]+$/.test(s)) return 'harus base64';
      return null;
    default:
      return null;
  }
}

/* ------------------------- tampilan / tombol ----------------------- */
const btn = (text, data) => ({ text, callback_data: data });
const grid = (items, per = 2) => {
  const rows = [];
  for (let i = 0; i < items.length; i += per) rows.push(items.slice(i, i + per));
  return rows;
};
function backCancel(withBack = true) {
  const row = [];
  if (withBack) row.push(btn('« Kembali', 'back'));
  row.push(btn('Batal', 'cancel'));
  return [row];
}
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/* --------------------------- Telegram API -------------------------- */
async function tg(env, method, payload) {
  const res = await fetch(`${TG_API}/bot${env.BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const j = await res.json().catch(() => ({}));
  return j;
}
async function send(env, chatId, text, rows) {
  const r = await tg(env, 'sendMessage', {
    chat_id: chatId, text, parse_mode: 'HTML',
    disable_web_page_preview: true,
    reply_markup: rows ? { inline_keyboard: rows } : undefined,
  });
  if (!r.ok) throw new Error('send gagal: ' + (r.description || 'unknown'));
  return r.result;
}
async function edit(env, chatId, messageId, text, rows) {
  const r = await tg(env, 'editMessageText', {
    chat_id: chatId, message_id: messageId, text, parse_mode: 'HTML',
    disable_web_page_preview: true,
    reply_markup: rows ? { inline_keyboard: rows } : undefined,
  });
  if (!r.ok && !/not modified/i.test(r.description || '')) throw new Error('edit gagal');
}
const ack = (env, id, text) => tg(env, 'answerCallbackQuery', { callback_query_id: id, text });

/* ------------------------------ router ----------------------------- */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/setup') return setup(request, url, env);
    if (request.method !== 'POST') return new Response('Cloudflare DNS Bot aktif.', { status: 200 });

    const got = request.headers.get('X-Telegram-Bot-Api-Secret-Token') || '';
    if (!env.WEBHOOK_SECRET || !timingSafeEqual(got, env.WEBHOOK_SECRET)) {
      return new Response('forbidden', { status: 403 });
    }

    let update;
    try { update = await request.json(); } catch { return new Response('bad request', { status: 400 }); }

    const user = updateUser(update);
    if (!user) return new Response('ok');

    // Ambil ID Durable Object unik per user Telegram
    const id = env.USERBOT.idFromName(String(user.id));
    const stub = env.USERBOT.get(id);

    try {
      const res = await stub.fetch('https://do/handle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ update, env }),
      });
      if (!res.ok) return new Response('retry', { status: 500 });
      return new Response('ok');
    } catch {
      return new Response('retry', { status: 500 });
    }
  },
};

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const updateUser = (u) => (u.message && u.message.from)
  || (u.callback_query && u.callback_query.from)
  || (u.edited_message && u.edited_message.from) || null;

async function setup(request, url, env) {
  if (!env.WEBHOOK_SECRET || url.searchParams.get('secret') !== env.WEBHOOK_SECRET) {
    return new Response('forbidden', { status: 403 });
  }
  const origin = `${url.protocol}//${url.host}`;
  const res = await tg(env, 'setWebhook', {
    url: `${origin}/webhook`,
    secret_token: env.WEBHOOK_SECRET,
    allowed_updates: ['message', 'callback_query'],
    drop_pending_updates: true,
  });
  const info = await tg(env, 'getWebhookInfo', {});
  return new Response(
    `setWebhook: ${JSON.stringify(res)}\n\ngetWebhookInfo: ${JSON.stringify(info)}`,
    { headers: { 'content-type': 'text/plain; charset=utf-8' } });
}

/* =========================== DURABLE OBJECT ========================== */
export class UserBot {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.storage = state.storage;
  }

  async fetch(request) {
    const { update, env } = await request.json();
    const user = updateUser(update);
    if (!user) return new Response('ok');
    const uidv = String(user.id);

    // dedupe
    const seenKey = `seen:${update.update_id}`;
    if (update.update_id !== undefined) {
      const seen = await this.storage.get(seenKey);
      if (seen) {
        if (update.callback_query) await ack(env, update.callback_query.id, '');
        return new Response('ok');
      }
      await this.storage.put(seenKey, 1);
    }

    try {
      if (update.callback_query) {
        const cq = update.callback_query;
        const chatId = cq.message && cq.message.chat.id;
        const messageId = cq.message && cq.message.message_id;
        await ack(env, cq.id, '');
        const st = await this.getState();
        const out = await this.onCallback(env, uidv, st, cq.data || '');
        await this.render(env, chatId, messageId, st, out, { callback: true });
      } else {
        const msg = update.message || update.edited_message;
        if (!msg || !msg.text) return new Response('ok');
        const chat = msg.chat;
        if (chat.type !== 'private') {
          await send(env, chat.id, 'Bot ini hanya melayani chat pribadi.');
          return new Response('ok');
        }
        const st = await this.getState();
        const out = await this.onText(env, uidv, st, msg);
        await this.render(env, chat.id, null, st, out, { token: msg.text });
      }
    } catch (e) {
      return new Response('retry', { status: 500 });
    }
    return new Response('ok');
  }

  /* --------------------------- state helpers -------------------------- */
  async getState() {
    return (await this.storage.get('state')) || { s: 'home', p: {} };
  }
  async setState(st) {
    st.p = st.p || {};
    await this.storage.put('state', st);
  }
  async clearState() { await this.storage.delete('state'); }
  async getAccounts() { return (await this.storage.get('accounts')) || []; }
  async setAccounts(list) { await this.storage.put('accounts', list); }
  findAccount(list, id) { return list.find((a) => a.id === id); }
  async cfFor(env, account) {
    return new Cloudflare(await decryptToken(env.ENCRYPTION_KEY, account.token));
  }

  /* ------------------------------ render ----------------------------- */
  async render(env, chatId, messageId, st, out, opts) {
    if (!out) return;
    if (out.drop && messageId) {
      await tg(env, 'deleteMessage', { chat_id: chatId, message_id: messageId });
    }
    if (opts.token && out.tokenConsumed) {
      await tg(env, 'deleteMessage', { chat_id: chatId, message_id: opts.token }).catch(() => {});
    }
    if (messageId && !out.drop) {
      await edit(env, chatId, messageId, out.text, out.rows);
    } else {
      await send(env, chatId, out.text, out.rows);
    }
  }

  /* ---------------------------- teks masuk --------------------------- */
  async onText(env, uidv, st, msg) {
    const text = msg.text.trim();
    if (text === '/start' || text === '/menu' || text === '/help') {
      st.s = 'home'; st.p = {};
      await this.setState(st);
      return this.viewHome(env, uidv);
    }
    if (text === '/cancel' || text === '/batal') {
      st.s = 'home'; st.p = {};
      await this.setState(st);
      return this.viewHome(env, uidv);
    }
    switch (st.s) {
      case 'acct_add_token': return this.addAccountToken(env, uidv, st, text);
      case 'rec_form': return this.formText(env, uidv, st, text);
      case 'rec_edit_form': return this.formText(env, uidv, st, text);
      default: return this.viewHome(env, uidv);
    }
  }

  /* ---------------------------- callback ----------------------------- */
  async onCallback(env, uidv, st, data) {
    const parts = data.split(':');
    const op = parts[0];
    const arg = parts.slice(1).join(':');

    if (op === 'noop') return null;
    if (op === 'home' || op === 'back' || op === 'cancel') {
      st.s = 'home'; st.p = {}; await this.setState(st);
      const v = await this.viewHome(env, uidv);
      return op === 'cancel' ? { ...v, drop: true } : v;
    }

    /* ---- akun ---- */
    if (op === 'ac_add') {
      st.s = 'acct_add_token'; st.p = {}; await this.setState(st);
      return {
        text: '<b>Tambah akun Cloudflare</b>\n\nKirim <b>API Token</b> Cloudflare.\n'
          + 'Permission minimal: <code>Zone:Read</code> + <code>DNS:Edit</code>.\n\n'
          + '<i>Pesan berisi token akan dihapus otomatis setelah diproses.</i>',
        rows: backCancel(false),
      };
    }
    if (op === 'ac_list') {
      const accts = await this.getAccounts();
      if (!accts.length) return this.viewHome(env, uidv);
      st.s = 'acct_list'; await this.setState(st);
      return {
        text: `<b>Akun Cloudflare (${accts.length})</b>\nPilih akun untuk melihat detail.`,
        rows: [...accts.map((a) => [btn(`${a.name}${a.active ? ' ✅' : ''} — ${a.id}`, `ac_sel:${a.id}`)]), backCancel(false)[0]],
      };
    }
    if (op === 'ac_sel') {
      const accts = await this.getAccounts();
      const a = this.findAccount(accts, arg);
      if (!a) return this.viewHome(env, uidv);
      st.s = 'acct_one'; st.p = { aid: a.id }; await this.setState(st);
      return {
        text: `<b>${esc(a.name)}</b>\nID: <code>${a.id}</code>\nStatus: ${a.active ? 'aktif ✅' : 'tidak aktif'}`,
        rows: [
          [btn('Jadikan aktif', `ac_use:${a.id}`)],
          [btn('Hapus akun', `ac_del:${a.id}`)],
          [btn('« Daftar akun', 'ac_list'), btn('Menu', 'home')],
        ],
      };
    }
    if (op === 'ac_use') {
      const accts = await this.getAccounts();
      if (!this.findAccount(accts, arg)) return this.viewHome(env, uidv);
      for (const a of accts) a.active = a.id === arg;
      await this.setAccounts(accts);
      st.s = 'home'; st.p = {}; await this.setState(st);
      return this.viewHome(env, uidv);
    }
    if (op === 'ac_del') {
      st.s = 'acct_del_confirm'; st.p = { aid: arg }; await this.setState(st);
      return {
        text: 'Hapus akun ini dari bot? Token Cloudflare tidak ikut dihapus, hanya dihapus dari penyimpanan bot.',
        rows: [[btn('Ya, hapus', `ac_deldel:${arg}`), btn('Batal', 'cancel')]],
      };
    }
    if (op === 'ac_deldel') {
      const accts = await this.getAccounts();
      const next = accts.filter((a) => a.id !== arg);
      if (!next.some((a) => a.active) && next.length) next[0].active = true;
      await this.setAccounts(next);
      st.s = 'home'; st.p = {}; await this.setState(st);
      return this.viewHome(env, uidv);
    }

    /* ---- zone ---- */
    if (op === 'zones') {
      const acct = await this.activeAccount();
      if (!acct) return this.viewHome(env, uidv);
      let list;
      try { list = await (await this.cfFor(env, acct)).zones(); }
      catch (e) { return { text: `Gagal mengambil zone: <code>${esc(e.message)}</code>`, rows: backCancel(false) }; }
      if (!list.length) return { text: 'Tidak ada zone. Pastikan token punya <code>Zone:Read</code>.', rows: backCancel(false) };
      st.s = 'zones'; st.p = {}; await this.setState(st);
      return {
        text: `<b>Pilih domain / zone</b>\nAkun: ${esc(acct.name)} · ${list.length} zone`,
        rows: [...grid(list.slice(0, 99).map((z) => btn(short(z.name, 30), `zone:${z.id}`)), 1), backCancel(false)[0]],
      };
    }
    if (op === 'zone') {
      const zone = await this.zoneOf(env, arg);
      if (!zone) return { text: 'Zone tidak ditemukan.', rows: backCancel(false) };
      st.s = 'zone'; st.p = { zid: arg, zname: zone.name }; await this.setState(st);
      return this.viewRecords(env, st, 0);
    }
    if (op === 'list') return this.viewRecords(env, st, Math.max(0, +arg || 0));

    /* ---- record ---- */
    if (op === 'rec') {
      const rec = await this.loadRecord(env, st, arg);
      if (!rec) return { text: 'Record tidak ditemukan.', rows: backCancel(false) };
      return {
        text: this.recSummary(rec),
        rows: [[btn('Ubah (edit)', `red:${rec.id}`), btn('Hapus', `rdel_confirm:${rec.id}`)], [btn('« Kembali ke daftar', 'list:0')]],
      };
    }
    if (op === 'red') {
      const rec = await this.loadRecord(env, st, arg);
      if (!rec) return { text: 'Record tidak ditemukan.', rows: backCancel(false) };
      st.s = 'rec_edit_form';
      st.p = { zid: st.p.zid, zname: st.p.zname, fid: rec.id, type: rec.type, fields: this.editFields(rec), idx: 0 };
      await this.setState(st);
      return this.promptField(env, st);
    }
    if (op === 'rf') {
      const i = +arg;
      const f = (st.p.fields || [])[i];
      if (!f) return this.viewHome(env, uidv);
      // buka field ini untuk diedit ulang
      f.done = false;
      st.p.idx = i;
      await this.setState(st);
      return this.promptField(env, st);
    }
    if (op === 'rtypes2') {
      if (!st.p.zid) return this.onCallback(env, uidv, st, 'zones');
      return {
        text: `<b>Tipe record lain</b> → <code>${esc(st.p.zname || '')}</code>\n\nSemua tipe yang didukung Cloudflare DNS.`,
        rows: [
          ...grid(ADVANCED.map((t) => btn(t, `rtype:${t}`)), 4),
          [btn('« Tipe Umum', 'add'), btn('« Daftar record', 'list:0')],
        ],
      };
    }
    if (op === 'rtype') {
      st.p.type = arg;
      st.p.fields = this.buildFields(arg, TYPE_INFO[arg] && TYPE_INFO[arg][1] === 1);
      st.s = 'rec_form'; st.p.fid = null; st.p.idx = 0; st.p.values = {};
      await this.setState(st);
      return this.promptField(env, st);
    }
    if (op === 'rclear') {
      st.p.clear = true; await this.setState(st);
      return this.promptField(env, st);
    }
    if (op === 'add') {
      const { zid, zname } = st.p;
      if (!zid) {
        // belum pilih zone: arahkan ke pemilihan domain
        return this.onCallback(env, uidv, st, 'zones');
      }
      st.s = 'rec_form';
      st.p = { zid, zname };
      await this.setState(st);
      return this.viewTypePicker(env, st);
    }
    if (op === 'ttl') {
      st.p.values = st.p.values || {};
      st.p.values.ttl = +arg;
      st.p.idx += 1;
      await this.setState(st);
      return this.promptField(env, st);
    }
    if (op === 'proxy') {
      st.p.values = st.p.values || {};
      st.p.values.proxied = arg === '1';
      st.p.idx += 1;
      await this.setState(st);
      return this.promptField(env, st);
    }
    if (op === 'renum') {
      st.p.values = st.p.values || {};
      st.p.values[st.p.fields[st.p.idx].key] = arg;
      st.p.fields[st.p.idx].done = true;
      st.p.fields[st.p.idx].value = arg;
      st.p.idx += 1;
      await this.setState(st);
      return this.promptField(env, st);
    }
    if (op === 'save') return this.doSave(env, st);
    if (op === 'rdel_confirm') {
      const rec = await this.loadRecord(env, st, arg);
      if (!rec) return { text: 'Record tidak ditemukan.', rows: backCancel(false) };
      st.s = 'rec_del_confirm'; st.p.rid = rec.id; await this.setState(st);
      return {
        text: `Hapus record ini?\n\n${this.recSummary(rec)}`,
        rows: [[btn('Ya, hapus permanen', 'rdel_go'), btn('Batal', 'cancel')]],
      };
    }
    if (op === 'rdel_go') {
      const rec = await this.loadRecord(env, st, st.p.rid);
      if (!rec) return { text: 'Record sudah tidak ada.', rows: backCancel(false) };
      try {
        const cf = await this.cfFor(env, await this.activeAccount());
        await cf.remove(st.p.zid, rec.id);
      } catch (e) {
        return { text: `Gagal menghapus: <code>${esc(e.message)}</code>`, rows: backCancel(false) };
      }
      st.s = 'zone'; st.p = { zid: st.p.zid, zname: st.p.zname }; await this.setState(st);
      return this.viewRecords(env, st, 0, '✅ Record dihapus.');
    }
    return this.viewHome(env, uidv);
  }

  /* ------------------------------ views ------------------------------ */
  async viewHome(env, uidv) {
    const accts = await this.getAccounts();
    const acct = accts.find((a) => a.active) || accts[0];
    const head = acct
      ? `Akun aktif: <b>${esc(acct.name)}</b> (${acct.id})\nAkun terdaftar: ${accts.length}`
      : 'Belum ada akun Cloudflare terdaftar.';
    return {
      text: `<b>Cloudflare DNS Manager</b>\n\n${head}\n\nPilih menu.`,
      rows: [
        [btn('🌐 Pilih Domain', 'zones')],
        [btn('➕ Tambah DNS', 'add'), btn('🗂 Kelola Akun', 'ac_list')],
        [btn('➕ Akun Baru', 'ac_add')],
      ],
    };
  }

  async activeAccount() {
    const accts = await this.getAccounts();
    return accts.find((a) => a.active) || accts[0] || null;
  }

  async zoneOf(env, zid) {
    const acct = await this.activeAccount();
    if (!acct) return null;
    const zones = await (await this.cfFor(env, acct)).zones();
    return zones.find((z) => z.id === zid) || null;
  }

  recSummary(r) {
    return `<b>${r.type}</b> <code>${esc(r.name)}</code>\nValue: <code>${esc(short(String(r.content), 300))}</code>\n`
      + `TTL: ${r.ttl === 1 ? 'Auto' : r.ttl}${r.proxied !== undefined ? `\nProxied: ${r.proxied ? 'ya' : 'tidak'}` : ''}`
      + `\nID: <code>${r.id}</code>`;
  }

  async viewRecords(env, st, page, notice = '') {
    const { zid, zname } = st.p;
    const acct = await this.activeAccount();
    if (!acct) return this.viewHome(env, '');
    let list;
    try { list = await (await this.cfFor(env, acct)).records(zid); }
    catch (e) { return { text: `Gagal mengambil record: <code>${esc(e.message)}</code>`, rows: backCancel(false) }; }
    list.sort((a, b) => a.name.localeCompare(b.name) || a.type.localeCompare(b.type));
    const PAGE = 8;
    const pages = Math.max(1, Math.ceil(list.length / PAGE));
    page = Math.min(Math.max(0, page), pages - 1);
    const slice = list.slice(page * PAGE, page * PAGE + PAGE);
    const rows = [];
    for (let i = 0; i < slice.length; i += 2) {
      const a = slice[i];
      const b = slice[i + 1];
      const lbl = (r) => `${r.type} ${short(r.name.replace('.' + zname, '') || '@', 18)}`;
      const row = [btn(lbl(a), `rec:${a.id}`)];
      if (b) row.push(btn(lbl(b), `rec:${b.id}`));
      rows.push(row);
    }
    const nav = [];
    if (page > 0) nav.push(btn('«', `list:${page - 1}`));
    nav.push(btn(`${page + 1}/${pages}`, 'noop'));
    if (page < pages - 1) nav.push(btn('»', `list:${page + 1}`));
    rows.push(nav);
    rows.push([btn('➕ Tambah DNS', 'add'), btn('🔄 Refresh', `list:${page}`)]);
    rows.push([btn('« Pilih Domain', 'zones'), btn('Menu', 'home')]);
    return {
      text: `${notice ? notice + '\n\n' : ''}<b>${esc(zname)}</b>\nTotal record: ${list.length} · halaman ${page + 1}/${pages}`,
      rows,
    };
  }

  async loadRecord(env, st, rid) {
    const { zid } = st.p;
    if (!zid) return null;
    try {
      const acct = await this.activeAccount();
      return await (await this.cfFor(env, acct)).record(zid, rid);
    } catch { return null; }
  }

  /* --------------------------- wizard fields -------------------------- */
  buildFields(type, proxiable) {
    const out = [];
    out.push({ key: 'name', label: 'Nama record (mis. www, @)', kind: 'name', min: 1, max: 255 });
    const fixed = FIXED_FIELDS[type];
    if (fixed) {
      for (const [key, label, kind, min, max] of fixed) {
        out.push({ key, label, kind, min: min || 1, max: max || 2048 });
      }
    }
    if (STRUCT[type]) {
      for (const [key, label, kind, min, max, en] of STRUCT[type]) {
        out.push({ key, label, kind, min, max, enum: en });
      }
    }
    out.push({ key: 'ttl', label: 'TTL', kind: 'ttl' });
    if (proxiable) out.push({ key: 'proxied', label: 'Proxy', kind: 'proxy' });
    return out;
  }

  editFields(rec) {
    const f = this.buildFields(rec.type, rec.proxiable === true);
    const pre = { name: rec.name, content: rec.content, ttl: rec.ttl, proxied: rec.proxied };
    if (rec.data && typeof rec.data === 'object') Object.assign(pre, rec.data);
    for (const x of f) {
      if (pre[x.key] !== undefined) { x.done = true; x.value = pre[x.key]; }
    }
    return f;
  }

  async viewTypePicker(env, st) {
    const { zname } = st.p;
    return {
      text: `<b>Tambah DNS</b> → <code>${esc(zname || '')}</code>\n\nPilih tipe record. Tombol <b>Tipe Lain</b> memuat semua tipe yang didukung Cloudflare.`,
      rows: [
        ...grid(BASIC.map((t) => btn(t, `rtype:${t}`)), 4),
        [btn('Tipe Lain ▾', 'rtypes2')],
        [btn('« Kembali ke daftar', 'list:0')],
      ],
    };
  }

  async promptField(env, st) {
    const fields = st.p.fields || [];
    while (st.p.idx < fields.length && fields[st.p.idx].done) st.p.idx++;
    const idx = st.p.idx;
    if (idx >= fields.length) return this.showPreview(env, st);
    const f = fields[idx];
    const header = st.p.fid ? '<b>Ubah record</b>' : `<b>Tambah ${st.p.type}</b>`;

    if (f.kind === 'ttl') {
      return {
        text: `${header}\n\nPilih TTL`,
        rows: [...grid(TTL_CHOICES.map(([t, v]) => btn(t, `ttl:${v}`)), 3), backCancel(false)[0]],
      };
    }
    if (f.kind === 'proxy') {
      return {
        text: `${header}\n\nProxied (orange cloud)?`,
        rows: [[btn('Proxied (🟠)', 'proxy:1'), btn('DNS only (⚪)', 'proxy:0')], ...backCancel(false)],
      };
    }
    if (f.enum) {
      return {
        text: `${header}\n\n${f.label}:\n${f.enum.map((e) => `• <code>${e}</code>`).join('\n')}`,
        rows: [...grid(f.enum.map((e) => btn(e, `renum:${e}`)), 3), ...backCancel(true)],
      };
    }
    const hint = { ipv4: 'Contoh: 192.0.2.1', ipv6: 'Contoh: 2001:db8::1', hex: 'Hex (tanpa spasi)', b64: 'Base64', host: 'Hostname tanpa titik di akhir' }[f.kind] || '';
    return {
      text: `${header}\n\nKirim <b>${esc(f.label)}</b>${hint ? `\n<i>${esc(hint)}</i>` : ''}`,
      rows: backCancel(true),
    };
  }

  async formText(env, uidv, st, text) {
    const f = (st.p.fields || [])[st.p.idx];
    if (!f) return this.viewHome(env, uidv);
    const val = text.trim();
    if (f.enum) {
      if (!f.enum.includes(val)) return { text: `Nilai harus salah satu: ${f.enum.join(', ')}`, rows: backCancel(true) };
    } else if (f.kind === 'int') {
      if (!isInt(val, f.min, f.max)) return { text: `Harus angka ${f.min}-${f.max}.`, rows: backCancel(true) };
    } else {
      const err = checkValue(f.kind, val, f.min, f.max);
      if (err) return { text: `Nilai tidak valid: ${esc(err)}`, rows: backCancel(true) };
    }
    st.p.values = st.p.values || {};
    st.p.values[f.key] = val;
    f.done = true;
    f.value = val;
    st.p.idx += 1;
    await this.setState(st);
    return this.promptField(env, st);
  }

  buildPayload(st) {
    // Nilai dasar: field yang sudah terisi (termasuk prefill saat edit),
    // lalu ditimpa input wizard terbaru.
    const v = {};
    for (const f of st.p.fields || []) {
      if (f.done && f.value !== undefined) v[f.key] = f.value;
    }
    Object.assign(v, st.p.values || {});
    return this.payloadFrom(st.p.type, st.p.zname, v);
  }

  payloadFrom(type, zname, v) {
    const name = fqdn(v.name || '@', zname);
    const body = { type, name, ttl: Number(v.ttl || 1) };
    if (TYPE_INFO[type] && TYPE_INFO[type][1] && v.proxied !== undefined) body.proxied = !!v.proxied;
    if (STRUCT[type]) {
      body.data = {};
      for (const [key, , kind] of STRUCT[type]) {
        const raw = v[key];
        body.data[key] = kind === 'int' ? Number(raw) : String(raw);
      }
      if (type === 'MX') body.priority = Number(v.priority);
      if (type === 'SRV') {
        body.data = { priority: Number(v.priority), weight: Number(v.weight), port: Number(v.port), target: String(v.target) };
        body.content = `${v.priority} ${v.weight} ${v.port} ${v.target}`;
      }
    } else {
      body.content = v.content;
    }
    return body;
  }

  async showPreview(env, st) {
    const body = this.buildPayload(st);
    const lines = ['<b>Konfirmasi record</b>', '', `Type: <code>${body.type}</code>`, `Name: <code>${esc(body.name)}</code>`];
    if (body.data) {
      for (const [k, v] of Object.entries(body.data)) lines.push(`${esc(k)}: <code>${esc(String(v))}</code>`);
    } else {
      lines.push(`Content: <code>${esc(String(body.content))}</code>`);
    }
    lines.push(`TTL: ${body.ttl === 1 ? 'Auto' : body.ttl}`);
    if (body.proxied !== undefined) lines.push(`Proxied: ${body.proxied ? 'ya' : 'tidak'}`);
    st.s = 'rec_confirm';
    await this.setState(st);
    const rows = [];
    if (st.p.fid) {
      // mode edit: izinkan ubah field satu-satu
      const labels = { name: 'Nama', content: 'Value', ttl: 'TTL', proxied: 'Proxy' };
      const extra = [];
      (st.p.fields || []).forEach((f, i) => {
        if (labels[f.key]) extra.push(btn(`✏️ ${labels[f.key]}`, `rf:${i}`));
      });
      for (let i = 0; i < extra.length; i += 3) rows.push(extra.slice(i, i + 3));
    }
    rows.push([btn('✅ Konfirmasi', 'save'), btn('Batal', 'cancel')]);
    return { text: lines.join('\n'), rows };
  }

  async doSave(env, st) {
    const body = this.buildPayload(st);
    const { zid, zname, fid } = st.p;
    try {
      const cf = await this.cfFor(env, await this.activeAccount());
      if (fid) await cf.update(zid, fid, body);
      else await cf.create(zid, body);
    } catch (e) {
      return { text: `Gagal menyimpan: <code>${esc(e.message)}</code>`, rows: [[btn('Menu', 'home')]] };
    }
    st.s = 'zone'; st.p = { zid, zname };
    await this.setState(st);
    return this.viewRecords(env, st, 0, fid ? '✅ Record diperbarui.' : '✅ Record dibuat.');
  }

  /* ------------------------------ akun add --------------------------- */
  async addAccountToken(env, uidv, st, token) {
    if (!/^[A-Za-z0-9_-]{30,200}$/.test(token)) {
      return { text: 'Format token tidak valid. Coba lagi atau /cancel.', rows: backCancel(false), tokenConsumed: true };
    }
    const cf = new Cloudflare(token);
    let accts;
    try {
      const zones = await cf.zones();
      const acctsList = await this.getAccounts();
      const id = String(acctsList.length + 1).padStart(2, '0');
      const encToken = await encryptToken(env.ENCRYPTION_KEY, token);
      const name = zones.length ? zones[0].name.split('.').slice(-2).join('.') : 'Cloudflare';
      accts = acctsList;
      const dup = accts.findIndex((a) => a.name === name);
      const entry = { id, name, token: encToken, active: true };
      accts.forEach((a) => { a.active = false; });
      if (dup >= 0) accts[dup] = entry; else accts.push(entry);
    } catch (e) {
      return { text: `Verifikasi token gagal: <code>${esc(e.message)}</code>`, rows: backCancel(false), tokenConsumed: true };
    }
    await this.setAccounts(accts);
    st.s = 'home'; st.p = {};
    await this.setState(st);
    const home = await this.viewHome(env, uidv);
    return { ...home, text: '✅ Akun tersimpan (token terenkripsi).\n\n' + home.text, tokenConsumed: true };
  }
}

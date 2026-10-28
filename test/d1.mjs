// Test harness D1 untuk worker.js
// Mock D1 memakai SQLite asli (better-sqlite3) supaya query diuji sungguhan.

import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';

const TG = [];
const CF = [];

globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  if (u.includes('api.telegram.org')) {
    const method = u.split('/').pop();
    const body = opts.body ? JSON.parse(opts.body) : {};
    TG.push({ method, body });
    return json({ ok: true, result: { message_id: 500 + TG.length } });
  }
  if (u.includes('api.cloudflare.com')) {
    const p = new URL(u).pathname;
    const method = opts.method || 'GET';
    const body = opts.body ? JSON.parse(opts.body) : undefined;
    CF.push({ method, path: p, body });
    if (p.endsWith('/zones')) {
      return json({ success: true, result: [{ id: 'z'.repeat(32), name: curZone }], result_info: { total_pages: 1 } });
    }
    if (p.endsWith('/dns_records') && method === 'GET') {
      return json({
        success: true,
        result: [{ id: 'r1' + 'a'.repeat(30), type: 'A', name: 'www.' + curZone, content: '192.0.2.1', ttl: 1, proxied: true, proxiable: true }],
        result_info: { total_pages: 1 },
      });
    }
    if (method === 'POST') return json({ success: true, result: { id: 'new', ...body } });
    if (method === 'PATCH') return json({ success: true, result: { id: 'p', ...body } });
    if (method === 'DELETE') return json({ success: true, result: { id: 'd' } });
    if (method === 'GET' && p.includes('/dns_records/')) {
      return json({ success: true, result: { id: 'r1' + 'a'.repeat(30), type: 'A', name: 'www.' + curZone, content: '192.0.2.1', ttl: 1, proxied: true, proxiable: true } });
    }
    return json({ success: true, result: {} });
  }
  throw new Error('unexpected fetch ' + u);
};
let curZone = 'example.com';
const json = (o) => new Response(JSON.stringify(o), { headers: { 'content-type': 'application/json' } });

/* ---------- D1 shim di atas node:sqlite ---------- */
function makeDB() {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8'));
  return {
    prepare(sql) {
      let params = [];
      const stmt = {
        bind(...a) { params = a; return stmt; },
        async first(col) {
          const row = db.prepare(sql).get(...params);
          if (!row) return null;
          return col ? row[col] : row;
        },
        async all() { return { results: db.prepare(sql).all(...params) }; },
        async run() {
          const r = db.prepare(sql).run(...params);
          return { meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
        },
      };
      return stmt;
    },
    async batch(stmts) {
      const out = [];
      db.exec('BEGIN');
      try {
        for (const s of stmts) out.push(await s.run());
        db.exec('COMMIT');
      } catch (e) {
        db.exec('ROLLBACK');
        throw e;
      }
      return out;
    },
    _raw: db,
  };
}

const KEY = Buffer.alloc(32, 9).toString('base64');
const SECRET = 'test-secret-1234567890';
const DB = makeDB();
const env = { BOT_TOKEN: 'T:tok', WEBHOOK_SECRET: SECRET, ENCRYPTION_KEY: KEY, DB };

const { UserBot } = await import('/root/cf-dns-bot/worker.js');
const bot = new UserBot({ storage: {} }, env);

let updId = 1000;
const results = [];
const ok = (name, cond, extra) => {
  results.push({ name, pass: !!cond });
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : '   <<< ' + (extra || '')}`);
};

const feed = (u) => bot.fetch(new Request('https://do/handle', {
  method: 'POST', body: JSON.stringify({ update: { ...u, update_id: updId++ }, env }),
}));
const text = (t) => feed({ message: { message_id: 10, from: { id: 999 }, chat: { id: 999, type: 'private' }, text: t } });
const last = () => [...TG].reverse().find((x) => x.method === 'sendMessage' || x.method === 'editMessageText');
const lastText = () => { const l = last(); return l ? l.body.text : ''; };
async function click(label) {
  const kb = last() && last().body.reply_markup && last().body.reply_markup.inline_keyboard;
  if (!kb) throw new Error('no keyboard');
  const flat = kb.flat();
  const b = flat.find((x) => x.text.includes(label));
  if (!b) throw new Error(`"${label}" tidak ada. Ada: ${flat.map((x) => x.text).join(' | ')}`);
  return feed({ callback_query: { id: 'cb' + updId, from: { id: 999 }, message: { message_id: 10, chat: { id: 999, type: 'private' } }, data: b.callback_data } });
}

/* =========================== TESTS =========================== */
console.log('\n--- skema D1 ---');
ok('tabel accounts ada', !!env.DB._raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'").get());
ok('tabel sessions ada', !!env.DB._raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'").get());
ok('tabel seen_updates ada', !!env.DB._raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='seen_updates'").get());

console.log('\n--- start ---');
await text('/start');
ok('menu tampil', lastText().includes('Cloudflare DNS Manager'));

console.log('\n--- tambah akun 1 dengan nama custom ---');
await click('Akun Baru');
ok('diminta nama akun', lastText().includes('Nama akun'));
await text('Utama');
ok('lalu diminta token', lastText().includes('API Token'));
await text('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
ok('akun 1 tersimpan', lastText().includes('Akun') && lastText().includes('Utama'), lastText());

console.log('\n--- tambah akun 2 (bug: akun 1 hilang) ---');
curZone = 'kedua.net';
await click('Akun Baru');
await text('Kedua');
await text('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
const rows2 = env.DB._raw.prepare('SELECT id,name,active FROM accounts WHERE user_id=? ORDER BY id').all('999');
ok('dua akun tetap ada di D1', rows2.length === 2, JSON.stringify(rows2));
ok('nama custom tersimpan', rows2.map((r) => r.name).join(',') === 'Utama,Kedua', JSON.stringify(rows2));
ok('hanya akun terbaru aktif', rows2.filter((r) => r.active === 1).length === 1 && rows2[1].active === 1, JSON.stringify(rows2));
await click('Kelola Akun');
const kbList = last().body.reply_markup.inline_keyboard.flat().map((b) => b.text).join(' | ');
ok('daftar menampilkan keduanya', kbList.includes('Utama') && kbList.includes('Kedua'), kbList);

console.log('\n--- ganti nama akun ---');
await click('Utama');
await click('Ganti nama');
await text('Produksi');
const rows3 = env.DB._raw.prepare('SELECT name FROM accounts WHERE user_id=? ORDER BY id').all('999');
ok('nama berubah', rows3[0].name === 'Produksi', JSON.stringify(rows3));

console.log('\n--- aktifkan akun ----');
await text('/start');
await click('Kelola Akun');
await click('Produksi');
await click('Jadikan aktif');
const act = env.DB._raw.prepare('SELECT id,active FROM accounts WHERE user_id=? AND active=1').all('999');
ok('akun pertama jadi aktif', act.length === 1 && act[0].id === '01', JSON.stringify(act));

console.log('\n--- hapus akun ---');
await click('Kelola Akun');
await click('Kedua');
await click('Hapus akun');
await click('Ya, hapus');
const rows4 = env.DB._raw.prepare('SELECT id,name FROM accounts WHERE user_id=?').all('999');
ok('akun kedua hilang', rows4.length === 1 && rows4[0].name === 'Produksi', JSON.stringify(rows4));

console.log('\n--- token terenkripsi ---');
const enc = env.DB._raw.prepare('SELECT token FROM accounts WHERE user_id=?').get('999').token;
ok('token prefix v1', enc.startsWith('v1.'), enc.slice(0, 12));
ok('plaintext token tidak ada', !enc.includes('aaaaaaaaaa'));

console.log('\n--- list zone & record masih jalan ---');
curZone = 'example.com';
await text('/start');
await click('Pilih Domain');
const zoneButtons = last().body.reply_markup.inline_keyboard.flat().map((b) => b.text).join(' | ');
ok('zone tampil', zoneButtons.includes('example.com'), zoneButtons);
await click('example.com');
ok('record tampil', lastText().includes('Total record'), lastText());

console.log('\n--- dedupe via D1 ---');
const n1 = TG.length;
await bot.fetch(new Request('https://do/handle', { method: 'POST', body: JSON.stringify({ update: { update_id: 777777, message: { message_id: 1, from: { id: 999 }, chat: { id: 999, type: 'private' }, text: '/start' } }, env }) }));
const n2 = TG.length;
await bot.fetch(new Request('https://do/handle', { method: 'POST', body: JSON.stringify({ update: { update_id: 777777, message: { message_id: 1, from: { id: 999 }, chat: { id: 999, type: 'private' }, text: '/start' } }, env }) }));
const n3 = TG.length;
ok('update_id sama diproses sekali', n2 > n1 && n3 === n2, `n1=${n1} n2=${n2} n3=${n3}`);

const failed = results.filter((r) => !r.pass);
console.log(`\n================ ${results.length - failed.length}/${results.length} PASS ================`);
if (failed.length) process.exit(1);

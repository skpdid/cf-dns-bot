// Test harness for /root/cf-dns-bot/worker.js
// Run: node --expose-gc test/run.mjs  (or just `node test/run.mjs`)
// Mocks Telegram API + Cloudflare API + Durable Object storage.

const TG = [];
const CF = [];
let tgFail = false;

/* ---------- global mocks ---------- */
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  if (u.includes('api.telegram.org')) {
    const method = u.split('/').pop();
    const body = opts.body ? JSON.parse(opts.body) : {};
    if (tgFail && method === 'sendMessage') {
      return new Response(JSON.stringify({ ok: false, description: 'boom' }), { status: 502 });
    }
    TG.push({ method, body });
    return new Response(JSON.stringify({ ok: true, result: { message_id: 500 + TG.length } }), {
      headers: { 'content-type': 'application/json' },
    });
  }
  if (u.includes('api.cloudflare.com')) {
    const parsed = new URL(u);
    const method = opts.method || 'GET';
    const body = opts.body ? JSON.parse(opts.body) : undefined;
    CF.push({ method, path: parsed.pathname, body });

    if (parsed.pathname.endsWith('/zones')) {
      return json({
        success: true,
        result: [
          { id: 'z'.repeat(32), name: 'example.com' },
          { id: 'y'.repeat(32), name: 'test.org' },
        ],
        result_info: { page: 1, total_pages: 1 },
      });
    }
    if (parsed.pathname.endsWith('/dns_records') && method === 'GET') {
      return json({
        success: true,
        result: [
          { id: 'r1' + 'a'.repeat(30), type: 'A', name: 'www.example.com', content: '192.0.2.1', ttl: 1, proxied: true, proxiable: true },
          { id: 'r2' + 'a'.repeat(30), type: 'MX', name: 'example.com', content: 'mail.example.com', ttl: 3600, proxiable: false, data: { priority: 10 } },
        ],
        result_info: { page: 1, total_pages: 1 },
      });
    }
    if (method === 'POST' && parsed.pathname.endsWith('/dns_records')) {
      return json({ success: true, result: { id: 'newid', ...body } });
    }
    if (method === 'PATCH') {
      return json({ success: true, result: { id: 'patched', ...body } });
    }
    if (method === 'DELETE') {
      return json({ success: true, result: { id: 'deleted' } });
    }
    if (method === 'GET' && parsed.pathname.includes('/dns_records/')) {
      return json({
        success: true,
        result: { id: 'r1' + 'a'.repeat(30), type: 'A', name: 'www.example.com', content: '192.0.2.1', ttl: 1, proxied: true, proxiable: true },
      });
    }
    return json({ success: true, result: {} });
  }
  return originalFetch(url, opts);
};
function json(obj) {
  return new Response(JSON.stringify(obj), { headers: { 'content-type': 'application/json' } });
}

/* ---------- fake Durable Object storage ---------- */
class FakeStorage {
  constructor() { this.map = new Map(); }
  async get(k) { return this.map.has(k) ? structuredClone(this.map.get(k)) : undefined; }
  async put(k, v) { this.map.set(k, structuredClone(v)); }
  async delete(k) { this.map.delete(k); }
}

/* ---------- fake env ---------- */
const KEY = Buffer.alloc(32, 9).toString('base64');
const SECRET = 'test-secret-1234567890';
const ENV = { BOT_TOKEN: 'T:tok', WEBHOOK_SECRET: SECRET, ENCRYPTION_KEY: KEY };

/* ---------- load modules under test ---------- */
const mod = await import('/root/cf-dns-bot/worker.js');
const worker = mod.default;
const UserBot = mod.UserBot;

const storage = new FakeStorage();
const bot = new UserBot({ storage }, ENV);

/* ---------- helpers ---------- */
let updateId = 1000;
const results = [];
function ok(name, cond, extra) {
  results.push({ name, pass: !!cond, extra });
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : '  <<< ' + (extra || '')}`);
  return cond;
}

async function feedUpdate(update) {
  const body = { ...update, update_id: updateId++ };
  const res = await bot.fetch(new Request('https://do/handle', {
    method: 'POST',
    body: JSON.stringify({ update: body, env: ENV }),
  }));
  return res;
}

async function sendText(text) {
  return feedUpdate({
    message: { message_id: 10, from: { id: 999 }, chat: { id: 999, type: 'private' }, text },
  });
}

async function click(labelPart) {
  // find the last sent message's inline keyboard and click matching button
  const last = [...TG].reverse().find((x) => x.method === 'sendMessage' || x.method === 'editMessageText');
  const kb = last && last.body.reply_markup && last.body.reply_markup.inline_keyboard;
  if (!kb) throw new Error('no keyboard in last message');
  const flat = kb.flat();
  const b = flat.find((x) => x.text.includes(labelPart));
  if (!b) throw new Error(`button "${labelPart}" not found. Buttons: ${flat.map((x) => x.text).join(' | ')}`);
  return feedUpdate({
    callback_query: {
      id: 'cb' + updateId,
      from: { id: 999 },
      message: { message_id: 10, chat: { id: 999, type: 'private' } },
      data: b.callback_data,
    },
  });
}

function lastText() {
  const last = [...TG].reverse().find((x) => x.method === 'sendMessage' || x.method === 'editMessageText');
  return last ? last.body.text + '\n' + JSON.stringify(last.body.reply_markup || {}) : '';
}

/* =========================== TESTS =========================== */

console.log('\n--- 1. start menu ---');
await sendText('/start');
ok('menu tampil', lastText().includes('Cloudflare DNS Manager') && lastText().includes('Akun Baru'));

console.log('\n--- 2. tambah akun (token valid) ---');
await click('Akun Baru');
ok('minta token', lastText().includes('Kirim') && lastText().includes('API Token'));
await sendText('abcdefghijklmnopqrstuvwxyz0123456789ABCDEF');
ok('akun tersimpan', lastText().includes('Akun tersimpan') || lastText().includes('Akun aktif'));
const stored = await storage.get('accounts');
ok('token tersimpan terenkripsi', stored && stored[0] && stored[0].token.startsWith('v1.'));
ok('plaintext token tidak tersimpan', stored && !JSON.stringify(stored).includes('abcdefghijklmnopqrstuvwxyz0123456789ABCDEF'));

console.log('\n--- 3. auto-detect zones ---');
await sendText('/start');
await click('Pilih Domain');
ok('daftar zone muncul', lastText().includes('example.com') && lastText().includes('test.org'));

console.log('\n--- 4. pilih zone -> daftar record ---');
await click('example.com');
ok('record list tampil', lastText().includes('Total record: 2') && lastText().includes('A www'));

console.log('\n--- 5. add A record (full chain) ---');
await click('Tambah DNS');
ok('tipe terdaftar lengkap', lastText().includes('A') && lastText().includes('AAAA') && lastText().includes('CNAME') && lastText().includes('TXT'));
await click('A');
ok('diminta nama', lastText().includes('Nama record'));
await sendText('api');
ok('diminta IPv4', lastText().includes('IPv4'));
await sendText('192.0.2.55');
ok('diminta TTL', lastText().includes('TTL'));
await click('Auto');
ok('diminta proxy', lastText().includes('Proxied'));
await click('DNS only');
ok('preview muncul', lastText().includes('Konfirmasi record') && lastText().includes('api.example.com'));
const beforePost = CF.filter((c) => c.method === 'POST').length;
await click('Konfirmasi');
const afters = CF.filter((c) => c.method === 'POST');
ok('record dibuat via API', afters.length === beforePost + 1, JSON.stringify(afters));
ok('payload benar', afters.at(-1).body.name === 'api.example.com' && afters.at(-1).body.type === 'A' && afters.at(-1).body.content === '192.0.2.55' && afters.at(-1).body.proxied === false, JSON.stringify(afters.at(-1).body));

console.log('\n--- 6. validasi input salah ---');
await click('Tambah DNS');
await click('A');
await sendText('www');
await sendText('999.1.1.1');
ok('IPv4 invalid ditolak', lastText().includes('tidak valid'));
await sendText('/cancel');

console.log('\n--- 7. MX pakai priority ---');
await sendText('/start');
await click('Pilih Domain');
await click('example.com');
await click('Tambah DNS');
await click('MX');
await sendText('@');
await sendText('10');
await click('Auto');
ok('preview MX ada priority', lastText().includes('priority'));
const beforeMx = CF.filter((c) => c.method === 'POST').length;
await click('Konfirmasi');
const mxCalls = CF.filter((c) => c.method === 'POST');
ok('MX terkirim dgn priority', mxCalls.length === beforeMx + 1 && String(mxCalls.at(-1).body.data.priority) === '10', JSON.stringify(mxCalls.at(-1)?.body));

console.log('\n--- 8. delete record dgn konfirmasi ---');
await sendText('/start');
await click('Pilih Domain');
await click('example.com');
await click('A www');
ok('detail record muncul', lastText().includes('Hapus'));
await click('Hapus');
ok('konfirmasi hapus', lastText().includes('Ya, hapus permanen'));
const beforeDel = CF.filter((c) => c.method === 'DELETE').length;
await click('Ya, hapus permanen');
ok('DELETE dieksekusi', CF.filter((c) => c.method === 'DELETE').length === beforeDel + 1);

console.log('\n--- 9. edit record ---');
await sendText('/start');
await click('Pilih Domain');
await click('example.com');
await click('A www');
await click('Ubah');
ok('edit mem-prefill nilai lama & langsung ke konfirmasi',
  lastText().includes('Konfirmasi record') && lastText().includes('192.0.2.1') && lastText().includes('www.example.com'));
const beforePatch = CF.filter((c) => c.method === 'PATCH').length;
await click('Konfirmasi');
const patches = CF.filter((c) => c.method === 'PATCH');
ok('PATCH ke record id lama', patches.length === beforePatch + 1 && patches.at(-1).path.includes('/dns_records/'), patches.at(-1)?.path);
ok('PATCH tidak mengubah isi (preserve)', patches.at(-1).body.content === '192.0.2.1' && patches.at(-1).body.type === 'A', JSON.stringify(patches.at(-1)?.body));

console.log('\n--- 10. dedupe update_id ---');
await sendText('/start');
const dupId = 99999;
const mkUpdate = { update_id: dupId, message: { message_id: 1, from: { id: 999 }, chat: { id: 999, type: 'private' }, text: '/start' } };
const n1 = TG.length;
await bot.fetch(new Request('https://do/handle', { method: 'POST', body: JSON.stringify({ update: mkUpdate, env: ENV }) }));
const n2 = TG.length;
await bot.fetch(new Request('https://do/handle', { method: 'POST', body: JSON.stringify({ update: mkUpdate, env: ENV }) }));
const n3 = TG.length;
ok('update_id sama tidak diproses 2x', n3 === n2 && n2 > n1, `n1=${n1} n2=${n2} n3=${n3}`);

console.log('\n--- 11. webhook auth ---');
const badRes = await worker.fetch(new Request('https://x.webhook/proom', {
  method: 'POST', headers: { 'X-Telegram-Bot-Api-Secret-Token': 'salah' },
  body: JSON.stringify({ update_id: 1, message: { from: { id: 1 }, chat: { id: 1, type: 'private' }, text: '/start' } }),
}), { ...ENV, USERBOT: fakeNS(storage) });
ok('secret salah -> 403', badRes.status === 403);

const goodRes = await worker.fetch(new Request('https://x.webhook/svc', {
  method: 'POST', headers: { 'X-Telegram-Bot-Api-Secret-Token': SECRET },
  body: JSON.stringify({ update_id: 2, message: { from: { id: 999 }, chat: { id: 999, type: 'private' }, text: '/start' } }),
}), { ...ENV, USERBOT: fakeNS(storage) });
ok('secret benar -> 200', goodRes.status === 200);

function fakeNS(st) {
  return {
    idFromName: (n) => n,
    get: () => ({ fetch: (url, init) => bot.fetch(new Request(url, init)) }),
  };
}

console.log('\n--- 12. private chat guard ---');
await feedUpdate({ message: { message_id: 5, from: { id: 999 }, chat: { id: -100, type: 'group' }, text: '/start' } });
ok('grup ditolak', lastText().includes('hanya melayani chat pribadi'));

/* ---------- summary ---------- */
const failed = results.filter((r) => !r.pass);
console.log(`\n================ ${results.length - failed.length}/${results.length} PASS ================`);
if (failed.length) {
  console.log('FAILED:');
  for (const f of failed) console.log(' -', f.name, f.extra || '');
  process.exit(1);
}

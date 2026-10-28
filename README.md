# Cloudflare DNS Manager — Telegram Bot

Bot Telegram untuk mengelola DNS di banyak akun Cloudflare, berjalan sepenuhnya di **Cloudflare Workers** (satu file `worker.js`, tanpa KV, tanpa server sendiri).

- **Multi-akun** — simpan banyak API Token Cloudflare, pilih akun aktif.
- **Auto-detect zone** — daftar domain diambil langsung dari akun, tinggal pilih lewat tombol.
- **CRUD DNS lengkap** — list, tambah, ubah, hapus, semua lewat inline button.
- **Semua tipe record** Cloudflare: `A AAAA CNAME TXT MX NS SRV CAA PTR NAPTR HTTPS SVCB URI DS DNSKEY CERT TLSA SMIMEA SSHFP LOC OPENPGPKEY`
- **Token terenkripsi** AES-256-GCM sebelum disimpan, dan pesan berisi token dihapus otomatis dari chat.
- **D1 database** untuk akun multi-akun, sesi wizard, dan dedupe update Telegram.
- **Async & aman** — webhook diverifikasi secret, update dedupe, Durable Object per user (tidak ada race condition saat tombol diklik cepat).

---

## 1. Prasyarat

| Kebutuhan | Keterangan |
|---|---|
| Akun Cloudflare | Free plan cukup (Durable Object SQLite) |
| Node.js 18+ | untuk `wrangler` |
| Bot Telegram | buat lewat [@BotFather](https://t.me/BotFather) → `/newbot` → simpan **token** |

---

## 2. Environment / Secret

Semua nilai disimpan sebagai **Secret** (terenkripsi di Cloudflare, tidak muncul di dashboard setelah disimpan).

| Nama | Wajib | Isi |
|---|---|---|
| `BOT_TOKEN` | ✅ | Token bot dari BotFather, format `123456789:AA...` |
| `WEBHOOK_SECRET` | ✅ | String acak panjang (min. 32 karakter). Dipakai Telegram untuk menandatangani request webhook dan dipakai sebagai password saat `/setup`. |
| `ENCRYPTION_KEY` | ✅ | **32 byte acak dalam base64** — kunci enkripsi API token Cloudflare |

> ⚠️ `ENCRYPTION_KEY` tidak bisa diganti setelah ada akun tersimpan. Kalau diganti, semua token lama tidak bisa didekripsi dan akun harus ditambahkan ulang. Simpan salinannya di password manager.

### Membuat nilai acak

```bash
# ENCRYPTION_KEY — tepat 32 byte, base64
openssl rand -base64 32

# WEBHOOK_SECRET — string acak 48 karakter
openssl rand -hex 24
```

Contoh output `openssl rand -base64 32`:
```
kQ7mZ2vX8pL1nR4tY6uJ0aS3dF5gH9jK2lM4nP6qR8s=
```
Itu yang dimasukkan ke `ENCRYPTION_KEY` (termasuk tanda `=` di akhir).

---

## 3. Membuat API Token Cloudflare

Bot membutuhkan token dengan izin **DNS**.

1. Buka [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
2. **Create Token** → **Create Custom Token**
3. Isi:
   - **Token name**: `telegram-dns-bot`
   - **Permissions**:
     - `Zone` → `Zone` → **Read**
     - `Zone` → `DNS` → **Edit**
   - **Zone Resources**: `Include` → `All zones` (atau pilih domain tertentu saja)
4. **Continue to summary** → **Create Token** → salin token (`v1.0-...`)

Satu token = satu akun. Ulangi untuk akun Cloudflare lain.

---

## 4. Deploy — Cara A: wrangler (disarankan)

```bash
# 1. masuk ke folder project
cd cf-dns-bot

# 2. install dependencies
npm install

# 3. login ke akun Cloudflare
npx wrangler login

# 4. buat Worker + Durable Object
npx wrangler deploy
```

Setelah deploy, wrangler menampilkan URL seperti:
```
https://cf-dns-bot.<subdomain>.workers.dev
```

Simpan URL itu. Lanjut ke **bagian 6 (set secret)**.

### Sekalian tanpa login browser (pakai API token akun Cloudflare)

```bash
export CLOUDFLARE_API_TOKEN="<token-dengan-izin-Workers-Scripts-Edit>"
npx wrangler deploy
```

---

## 5. Deploy — Cara B: dashboard (tanpa CLI)

1. Buka **Cloudflare Dashboard** → **Workers & Pages** → **Create**
2. Pilih **Start with Hello World!** → **Deploy**
3. Klik **Edit code** → hapus semua isi → tempel seluruh isi `worker.js` → **Deploy**
4. **Durable Object wajib dibuat lewat migration**, dan migration hanya bisa dijalankan oleh wrangler. Tanpa langkah ini Worker akan error saat diakses.
   Jalankan sekali dari komputer/terminal:
   ```bash
   npx wrangler deploy    # memakai wrangler.toml di folder ini
   ```
   Perintah itu membuat class `UserBot` + binding `USERBOT` pada Worker dengan nama `cf-dns-bot`. Kalau nama Worker di dashboard berbeda, ubah `name` di `wrangler.toml` agar sama, atau ganti nama Worker di dashboard.
5. Set secret (bagian 6) dan daftarkan webhook (bagian 7).

> Ringkasnya: cara B hanya praktis kalau kamu tetap menjalankan `npx wrangler deploy` sekali untuk migration. Kalau tidak mau install wrangler sama sekali, pakai **Cara A**.

---

## 6. Buat dan siapkan database D1

Di Dashboard Cloudflare:

1. Buka **Workers & Pages → D1 SQL Database → Create database**.
2. Gunakan nama `cf-dns-bot`.
3. Salin **Database ID** dari halaman database.
4. Di `wrangler.toml`, ganti:
   ```toml
   database_id = "REPLACE_WITH_D1_DATABASE_ID"
   ```
   dengan Database ID tersebut.
5. Jalankan schema ke database remote:
   ```bash
   npx wrangler d1 execute cf-dns-bot --remote --file=./schema.sql
   ```
6. Commit dan push `wrangler.toml` + `schema.sql`, lalu biarkan GitHub build berjalan.

Binding yang dipakai kode adalah `DB`. Jangan menghapus atau mengganti nama binding ini.

## 7. Set Secret

### Lewat wrangler (Cara A)

```bash
npx wrangler secret put BOT_TOKEN
# tempel token bot, Enter

npx wrangler secret put WEBHOOK_SECRET
# tempel string acak, Enter

npx wrangler secret put ENCRYPTION_KEY
# tempel hasil `openssl rand -base64 32`, Enter
```

### Lewat dashboard

**Worker** → **Settings** → **Variables and Secrets** → **Add** → pilih tipe **Secret** → isi nama & nilai untuk ketiga variabel di atas.

Setelah menambah secret, **deploy ulang** (`npx wrangler deploy`) agar binding aktif.

---

## 7. Daftarkan Webhook

Buka di browser:

```
https://cf-dns-bot.<subdomain>.workers.dev/setup?secret=<WEBHOOK_SECRET>
```

Ganti `<WEBHOOK_SECRET>` dengan nilai yang kamu set di langkah 6.

Respons sukses terlihat seperti:

```
setWebhook: {"ok":true,"result":true,"description":"Webhook was set"}

getWebhookInfo: {"ok":true,"result":{"url":"https://.../webhook","has_custom_certificate":false,"pending_update_count":0}}
```

Kalau `"url"` sudah terisi dan `pending_update_count` 0, webhook aktif.

---

## 8. Pakai Bot

Buka bot di Telegram → **Start** → `/start`.

| Menu | Fungsi |
|---|---|
| 🌐 **Pilih Domain** | Ambil daftar zone dari akun Cloudflare aktif, lalu pilih domain |
| ➕ **Tambah DNS** | Wizard tambah record: pilih tipe → isi field → TTL → proxy → konfirmasi |
| 🗂 **Kelola Akun** | Lihat, aktifkan, atau hapus akun Cloudflare |
| ➕ **Akun Baru** | Kirim API Token Cloudflare untuk ditambahkan |

Di dalam domain: daftar record (dengan paging), klik record untuk **Ubah** atau **Hapus**.

### Alur tambah record

```
Tambah DNS
  → pilih tipe (A / AAAA / CNAME / TXT / MX / NS / SRV / CAA / Tipe Lain ▾)
  → nama record         mis. www  atau  @  untuk root
  → value               mis. 192.0.2.1
  → TTL                 Auto / 60 / 300 / ... / 86400
  → proxy               Proxied (🟠) atau DNS only (⚪)  (hanya A/AAAA/CNAME)
  → Konfirmasi
```

Field yang diminta menyesuaikan tipe. Contoh:
- **MX** → priority + target
- **SRV** → priority, weight, port, target
- **CAA** → flags, tag (tombol), value
- **DS / DNSKEY / TLSA / SMIMEA / SSHFP / CERT** → komponen numerik + hex/base64
- **HTTPS / SVCB / LOC / NAPTR / OPENPGPKEY** → value mentah

### Alur ubah record

Klik record → **Ubah** → semua nilai lama otomatis terisi → tekan **Konfirmasi** untuk simpan apa adanya, atau **✏️ Nama / Value / TTL / Proxy** untuk mengubah field tertentu saja.

Hanya field yang berubah dikirim ke Cloudflare (PATCH), jadi data kompleks tidak hilang.

---

## 9. Struktur project

```
cf-dns-bot/
├── worker.js          # seluruh bot (routing, DO, wizard, Cloudflare client)
├── wrangler.toml      # config Worker + binding Durable Object + migration
├── package.json
└── test/
    └── run.mjs        # 28 test dengan mock Telegram & Cloudflare API
```

## 10. Menjalankan test

```bash
npm test
```

Output akhir: `================ 28/28 PASS ================`

Test memakai mock penuh — tidak menyentuh API Telegram maupun Cloudflare asli, tidak butuh kredensial.

---

## 11. Batasan

- **Bukan registrar** — bot mengelola DNS record, bukan membeli/mendaftarkan domain.
- **NS record** di apex biasanya dikelola Cloudflare dan tidak bisa diubah lewat API.
- Record yang di-proxy hanya `A`, `AAAA`, `CNAME`.
- `HTTPS` pada nama yang proxied di-generate otomatis Cloudflare — record manual tidak akan disajikan.
- **Akses tunggal** — tidak ada `ALLOWED_USER_IDS` (sesuai permintaan: bot private). Artinya **siapa pun yang menemukan bot dan tahu username-nya bisa memakai bot ini** dan melihat/mengubah DNS di akun yang tersimpan. Kalau ingin dibatasi, tambahkan pengecekan `user.id` di `worker.js` (fungsi `fetch` di `export default`) sebelum memanggil Durable Object.
- Kuota free plan: 100.000 request/hari, Durable Object SQLite 5 GB — jauh lebih dari cukup.

## 12. Troubleshooting

| Gejala | Penyebab | Solusi |
|---|---|---|
| Bot diam saja | webhook belum diset | Buka ulang URL `/setup?secret=...` |
| `/setup` → `forbidden` | secret di URL ≠ `WEBHOOK_SECRET` | Cocokkan nilainya |
| `ENCRYPTION_KEY harus 32 byte base64` | kunci bukan 32 byte | `openssl rand -base64 32` |
| `Gagal mengambil zone` | token kurang izin | Tambah `Zone:Read` |
| `Gagal menyimpan` | token kurang izin | Tambah `DNS:Edit` |
| Semua tombol jadi tidak merespons | sesi di-reset | Kirim `/start` |
| Record manual HTTPS tidak muncul | nama proxied | Set DNS only, atau biarkan Cloudflare generate |

Log real-time:

```bash
npx wrangler tail
```

## 13. Perintah bot

| Perintah | Fungsi |
|---|---|
| `/start` | Menu utama |
| `/menu` | Menu utama |
| `/cancel`, `/batal` | Batalkan wizard yang sedang berjalan |

Bot hanya melayani **private chat**; pesan dari grup ditolak.

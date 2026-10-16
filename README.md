# Kontaq

Dashboard WhatsApp Business menggunakan **Meta WhatsApp Cloud API** resmi.
Node.js + Express, EJS + Tailwind, Socket.IO, database JSON (MVP).

## Menjalankan

```bash
npm install
cp .env.example .env      # isi SESSION_SECRET (min. 32 karakter acak) dan PUBLIC_URL
npm start                 # http://localhost:3000
```

Buka aplikasi → buat akun admin pertama → **Pengaturan › Koneksi Meta**:

1. Isi Phone Number ID, WABA ID, Access Token (System User permanen dengan izin
   `whatsapp_business_messaging` + `whatsapp_business_management`), App Secret, dan Verify Token.
2. Klik **Uji koneksi**, lalu **Subscribe app ke WABA**.
3. Di Meta App Dashboard › WhatsApp › Configuration, isi Callback URL `PUBLIC_URL/webhook` dan
   Verify Token yang sama, lalu subscribe field `messages`, `message_template_status_update`, `calls`.

Webhook wajib HTTPS publik. Untuk pengujian lokal gunakan tunnel (mis. `cloudflared`/`ngrok`).

Produksi dengan PM2: `npm run pm2` (set `COOKIE_SECURE=true` dan `TRUST_PROXY=true` di belakang nginx/HTTPS).

## Struktur

| File | Isi |
|---|---|
| `server.js` | Backend: DB JSON, autentikasi, Graph API, webhook, REST API, antrean campaign, Socket.IO |
| `views/index.ejs` | Seluruh UI (login, dashboard, inbox, kontak, template, campaign, panggilan, pengaturan) |
| `public/style.css` | Token warna (terang/gelap) dan komponen |
| `data/` | Dibuat otomatis saat berjalan: `db.json`, `secret.key` — jangan di-commit |

## Notifikasi WhatsApp (gateway)

Selain notifikasi di browser, tiap pengguna dapat menerima notifikasi ke **nomor WhatsApp pribadinya** lewat
WA gateway pihak ketiga (`POST` dengan header `x-api-key`, body `{ device, to, message }`).

1. Admin: **Pengaturan › Gateway WA** — isi URL, Device, dan API key (atau `WA_GATEWAY_*` di `.env`), lalu kirim pesan tes.
2. Tiap pengguna: **Pengaturan › Notifikasi & keamanan › Notifikasi WhatsApp** — isi nomor, pilih jenis
   (pesan masuk, percakapan ditugaskan, panggilan masuk), lalu aktifkan sakelar. Opsi "Hanya kirim saat Kontaq
   tidak sedang terbuka" aktif secara bawaan.

Pesan masuk mengikuti hak akses: percakapan yang sudah ditugaskan hanya memberi tahu agen pemiliknya; yang belum
ditugaskan memberi tahu semua pengguna. Maksimal satu notifikasi per percakapan tiap 2 menit per pengguna.

## Log pesan (admin)

Menu **Log pesan** menampilkan semua pesan keluar via Cloud API beserta totalnya: dari Dashboard/Inbox, Campaign,
Auto reply, dan pesan yang dikirim **di luar Kontaq** dengan nomor bisnis yang sama (terdeteksi dari webhook status;
isinya tidak tersedia, hanya status dan biaya). Filter: nomor/Message ID, tanggal, status, jenis, sumber, campaign,
template, nomor bisnis, gagal saja; paginasi di server; ekspor CSV; detail per pesan (payload dengan nomor
disamarkan, respons HTTP/Meta, error, riwayat status, estimasi biaya).

Status dipisah per tahap: **request API** → **Diterima Meta** (ada message ID) → **Terkirim / Sampai / Dibaca / Gagal**
hanya dari webhook. HTTP 200 tidak dianggap terkirim. Request yang gagal juga dicatat. Estimasi biaya memakai
`pricing` dari webhook × tarif per kategori di kartu Biaya Meta. Log menyimpan 20.000 entri terakhir;
pesan lama diisi otomatis sekali saat server pertama kali berjalan dengan fitur ini.

## Flow otomatis (admin)

Menu **Flow otomatis** menyusun alur tanpa coding, mis. *pesan masuk → cek kata kunci → kirim balasan → teruskan ke agen*.
Flow berbentuk pohon: langkah **Kondisi** membuat cabang **Ya**/**Tidak**, sehingga flow tidak bisa berputar (loop).

- **Kondisi:** kata kunci, jadwal (hari + jam), jam kerja (dari Auto reply), label kontak, kontak baru, jenis pesan, sudah ditugaskan.
- **Aksi:** kirim pesan (teks/gambar/tombol), teruskan ke agen (agen tertentu, bergiliran, atau yang paling sedikit menangani),
  tambah/hapus label, ubah status, catatan internal, **Tunggu** (1 menit–23 jam).
- **Jadwal flow:** tanggal aktif mulai/sampai, jeda saat CS aktif, jeda menjalankan ulang per percakapan.
- **Uji flow:** simulasi dengan contoh pesan, hari/jam, label — tidak mengirim apa pun; jalur yang dilewati disorot.

Flow aktif dicek dari atas ke bawah. Flow pertama yang menjalankan aksi menghentikan pengecekan, dan Auto reply tidak dijalankan
untuk pesan itu (tidak ada balasan ganda). Pesan hanya dikirim selama jendela layanan 24 jam terbuka (dicek ulang setelah Tunggu),
maksimal 10 pesan otomatis per jam per percakapan. Langkah Tunggu tersimpan di DB dan berlanjut setelah server restart; dibatalkan
bila pelanggan mengirim pesan lagi atau CS membalas (bisa dimatikan). Riwayat jalan tampil di daftar flow dan di editor.

## Pemakaian di HP

Buka Kontaq di browser HP (Chrome/Safari) lewat **HTTPS**. Mikrofon untuk panggilan hanya diizinkan lewat HTTPS.
Pilih "Tambahkan ke layar utama" agar terbuka layar penuh seperti aplikasi.
Biarkan Kontaq terbuka di layar agar panggilan masuk berdering. Jika layar sempat mati, panggilan yang masih
berdering muncul lagi saat aplikasi dibuka. Notifikasi saat browser tertutup memerlukan Web Push dan belum tersedia.

## Catatan

- Token & App Secret disimpan terenkripsi (AES-256-GCM) di server dan tidak pernah dikirim ke browser;
  media diambil melalui proxy `/api/media/:id`.
- Pesan bebas hanya dapat dikirim dalam jendela layanan 24 jam sejak pesan terakhir pelanggan;
  di luar itu hanya template APPROVED (ditegakkan di server).
- Peran: **admin** (akses penuh) dan **agen** (percakapan miliknya/belum ditugaskan, kontak, kirim template).
- Database JSON ditujukan untuk satu instance & tim kecil. Untuk multiuser/produksi, migrasikan lapisan
  data di bagian 2 `server.js` ke MySQL. Jangan jalankan PM2 dalam mode cluster dengan DB JSON.
- Calling API (WebRTC di browser): menerima panggilan dari pelanggan, dan telepon balik ke pelanggan yang
  memberi izin (aktifkan "Izinkan telepon balik" di menu Panggilan). Ketersediaan bergantung pada akun dan negara di Meta.
- Header template media (gambar/video/dokumen) belum dapat dibuat dari formulir — buat di WhatsApp
  Manager lalu sinkronkan; template tersebut tetap dapat dikirim (dengan URL media).

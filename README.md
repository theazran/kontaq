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
   Verify Token yang sama, lalu subscribe field `messages`, `message_template_status_update`, `calls`
   (dan untuk fitur Grup: `group_lifecycle_update`, `group_participants_update`, `group_settings_update`, `group_status_update`;
   untuk WhatsApp Flows: `flows`).

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
   (pesan masuk, percakapan ditugaskan, panggilan masuk, pengingat jatuh tempo), lalu aktifkan sakelar. Opsi "Hanya kirim saat Kontaq
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
maksimal 30 pesan otomatis per jam per percakapan. Langkah Tunggu tersimpan di DB dan berlanjut setelah server restart; dibatalkan
bila pelanggan mengirim pesan lagi atau CS membalas (bisa dimatikan). Riwayat jalan tampil di daftar flow dan di editor.

### Tanya jawab, variabel, dan API Request

- **Tanya pelanggan:** kirim pertanyaan lalu tunggu balasan berikutnya, simpan ke variabel (`{{nama}}` dan `{{nama_label}}`).
  Jenis jawaban: teks (panjang & format divalidasi), pilihan (≤ 3 tombol, selebihnya pesan daftar), atau tanggal (tombol tanggal
  terdekat + "Tanggal lain"; ketikan `21-10-2026`, `21/10/2026`, `2026-10-21`, `21 okt`, `besok` diterima; nilai selalu `YYYY-MM-DD`).
  Cabang **Dijawab** / **Tidak valid** (setelah kesempatan ulang habis). Kata pembatal (bawaan `batal`) dan batas waktu menjawab
  diatur per flow/langkah; bila CS membalas, pertanyaan yang menunggu dibatalkan.
- **API Request:** GET/POST ke HTTPS dengan variabel di URL (otomatis di-URL-encode) atau body JSON; respons JSON disimpan ke variabel
  (`{{hasil.field}}`, `{{hasil_status}}`, `{{hasil_error}}`). Cabang **Berhasil** bila HTTP 2xx, JSON valid, dan field penanda (opsional)
  sesuai; selain itu **Gagal**. Pengaman: timeout 1–20 dtk, respons maks. 512 KB, tanpa redirect, host tidak boleh berisi variabel,
  alamat jaringan lokal/privat ditolak (termasuk IP literal & DNS). API key/token disimpan di **Kredensial API** (terenkripsi) dan
  dipakai sebagai `{{secret.NAMA}}`; tidak pernah dikirim ke browser atau dicatat di log.
- **Variabel & filter** di semua teks: `{{tanggal|tanggal}}`, `{{item.jam|jam}}`, `{{item.harga|rupiah}}`,
  `{{x|default:-}}`, `{{data.length}}`. Kondisi **Variabel**: sama dengan, mengandung, lebih/kurang dari, kosong/tidak kosong.
- **Kirim daftar:** langkah Kirim pesan dapat mengulang daftar dari variabel (mis. hasil API), dipecah per N item (maks. 10 pesan).
- **Uji flow** dapat memakai jawaban uji dan memanggil API GET sungguhan untuk melihat struktur respons asli.

## WhatsApp Flows (admin)

Menu **WhatsApp Flows** mengelola formulir interaktif resmi WhatsApp lewat
[Flows API](https://developers.facebook.com/docs/whatsapp/flows/reference/flowsapi) (memakai WABA ID & token di Koneksi Meta).

- **Kelola:** sinkronkan flow dari WABA, buat flow baru dari contoh (formulir kontak, survei, janji temu) atau gandakan (clone),
  susun lewat **editor visual** (di bawah) atau ubah Flow JSON langsung (Meta memvalidasi dan mengembalikan error per baris),
  pratinjau resmi Meta, terbitkan, nonaktifkan (deprecate), hapus draf. Flow yang sudah terbit tidak dapat diubah — gandakan untuk versi baru.
- **Kirim:** dari Inbox (ikon formulir di kolom pesan) selama jendela 24 jam terbuka; admin dapat mengirim mode draf untuk uji.
  Di luar jendela 24 jam, kirim template yang memiliki tombol **Flow** — Kontaq mengisi `flow_token` otomatis (juga untuk campaign).
- **Jawaban:** `nfm_reply.response_json` dicocokkan dengan pengiriman lewat `flow_token`, tampil sebagai daftar isian di chat dan
  di tab **Jawaban** per flow (ekspor CSV). Kunci `payload` pada aksi `complete` di Footer menjadi nama isian.
- **Flow otomatis:** langkah **Kirim WhatsApp Flow** mengirim formulir lalu menunggu jawaban; isian tersedia sebagai
  `{{formulir.nama_field}}`. Cabang **Diisi** / **Tidak diisi** (dijalankan saat batas waktu habis, mis. untuk pengingat).
- **Webhook `flows`:** perubahan status (terbit, dibatasi, diblokir, nonaktif) dan peringatan kesehatan dicatat di halaman flow.

Kontaq mendukung flow tanpa endpoint (navigasi antar-screen + `complete`). Flow ber-endpoint (`data_exchange`) dapat dikirim
dan jawabannya dicatat, tetapi pertukaran datanya dilayani oleh endpoint terenkripsi milik Anda sendiri.

### Editor visual

Tab **Editor visual** di halaman flow menyusun formulir tanpa menulis JSON:

- **Header:** nama, kategori, status, indikator *belum disimpan*, tombol Simpan (Ctrl+S), Pratinjau, Validasi, Publikasikan,
  dan menu tindakan sesuai status (pratinjau resmi Meta, lihat/unduh Flow JSON, gandakan, muat ulang, hapus draf / nonaktifkan).
  Meninggalkan halaman dengan perubahan belum disimpan memunculkan konfirmasi.
- **Layar (kiri):** tambah, buka, ganti nama, gandakan, hapus (dengan konfirmasi), dan urutkan dengan seret-lepas (mouse, sentuh,
  atau tombol panah pada pegangan). Layar punya ID internal stabil, jadi tujuan tombol tetap benar saat ID layar diganti atau urutan diubah;
  menghapus layar mengalihkan tombol yang mengarah ke layar itu ke tujuan berikutnya.
- **Editor (tengah):** judul & ID layar (otomatis dari judul, dapat diubah), daftar komponen (urutkan, gandakan, hapus), properti
  komponen terpilih saja, serta tombol & navigasi (lanjut ke layar lain atau *Selesai — kirim data*).
- **Katalog komponen:** Judul, Subjudul, Teks isi, Keterangan, Rich text, Tautan, Gambar (dikompres ≤ 300 KB), Jawaban singkat/panjang,
  Dropdown, Pilihan tunggal/ganda, Pemilih chip, Pemilih tanggal, Kalender, Persetujuan. Komponen yang butuh versi Flow JSON lebih baru
  (RichText 5.1, CalendarPicker 6.1, ChipsSelector 6.3, pola regex 6.2, buka URL 6.0) ditandai.
- **Pratinjau (kanan):** tampilan ponsel yang langsung mengikuti setiap perubahan; klik komponen untuk mengeditnya. Mode **Uji alur**
  mencoba formulir dari layar pertama: validasi wajib/format, navigasi & kembali, lalu menampilkan data yang *akan* dikirim — data uji
  tidak dikirim ke server dan tidak tercatat sebagai jawaban.
- **Data antarlayar otomatis:** isian dibawa ke layar berikutnya (dapat ditampilkan dengan `${data.nama_field}`, mis. layar ringkasan)
  dan Footer *Selesai* mengirim semua isian lewat `payload`, sehingga jawaban tetap tercatat di tab Jawaban.
- **Validasi:** pemeriksaan lokal (batas karakter, jumlah pilihan & komponen per layar, nama field unik, tujuan navigasi, layar tak terjangkau,
  versi) ditambah error validasi Meta dari penyimpanan terakhir; klik error untuk membuka komponennya.

Flow yang memakai fitur di luar editor (endpoint/`data_exchange`, `data-source` dinamis) dibuka hanya baca di editor visual dan tetap
dapat diubah di tab **Flow JSON**. Komponen lain yang belum didukung (mis. `If`, `PhotoPicker`) disalin apa adanya.

## Grup WhatsApp (admin)

Menu **Grup** memakai [Groups API](https://developers.facebook.com/documentation/business-messaging/whatsapp/groups/get-started) resmi.
Syarat: nomor bisnis berstatus **Official Business Account (OBA)**; grup hanya-undangan, maks. 8 peserta.

- **Kelola grup:** buat grup (nama, deskripsi, mode bergabung langsung / perlu persetujuan), ubah nama/deskripsi/foto,
  hapus grup, sinkronkan grup aktif dari Meta, dan muat ulang info grup.
- **Tautan undangan:** salin, buat tautan baru (tautan lama langsung tidak berlaku), dan kirim undangan ke kontak —
  pesan teks bila jendela 24 jam terbuka, selain itu template APPROVED (variabel `{{link}}`; tombol URL undangan diisi otomatis).
  Riwayat undangan menandai kontak yang sudah bergabung berdasarkan webhook.
- **Pesan grup:** teks, media, dan template; balasan kutipan; status dari webhook (gabungan semua peserta). Pesan yang gagal tetap
  tercatat beserta error-nya, dan masuk ke **Log pesan** dengan sumber "Grup". Pesan interaktif, lokasi, dan panggilan tidak didukung di grup.
- **Peserta:** daftar peserta, keluarkan peserta, setujui/tolak permintaan bergabung. Bisnis tidak dapat menambahkan peserta langsung.

Buat, hapus, ubah pengaturan, dan keluarkan peserta bersifat asinkron di Meta: Kontaq menampilkan "Menunggu konfirmasi Meta"
dan baru mengubah data setelah webhook grup tiba. Pesan masuk dari grup (`group_id`) tidak dibuat sebagai percakapan pribadi.
Grup yang dibuat di luar Kontaq dengan nomor yang sama tercatat otomatis saat event webhook-nya masuk.

## Kirim media & pesan kaya (Inbox)

Composer mengikuti alur WhatsApp: ikon emoji, tombol ＋ untuk lampiran, dan tombol kanan berubah antara **mikrofon**
(kosong) dan **kirim** (ada teks).

- **Foto & video:** pilih beberapa file sekaligus, seret & lepas ke area chat, atau tempel (Ctrl+V). Layar pratinjau
  menampilkan tiap file dengan keterangan per file, tombol **HD**, pilihan *kirim sebagai dokumen*, progres unggah per file,
  dan kirim beruntun. Gambar dikompres ke sisi terpanjang 1600 px (HD: 4096 px); WebP/GIF/BMP/AVIF dikonversi ke JPEG.
  File di luar batas Meta (video > 16 MB, format tak didukung) otomatis dialihkan menjadi dokumen.
- **Dokumen:** kartu dengan ikon per jenis (PDF/DOC/XLS/PPT/ZIP), nama, ukuran, dan tombol unduh. MIME diperbaiki dari
  ekstensi bila browser mengirim `application/octet-stream`.
- **Pesan suara:** rekam dari composer (jeda, batal, gelombang langsung, maks. 15 menit). Rekaman WebM/Opus Chrome/Edge
  di-remux ke **OGG/Opus** di server (syarat `voice: true` Meta) tanpa encode ulang; Safari (AAC) dikirim sebagai audio biasa.
  Pemutar menampilkan gelombang, durasi berjalan, kecepatan 1×/1,5×/2×, dan klik untuk melompat (HTTP Range).
- **Stiker:** pustaka stiker bersama; buat dari gambar apa pun (otomatis 512×512 WebP ≤ 100 KB) atau simpan stiker yang
  dikirim pelanggan. Validasi ukuran & dimensi sesuai aturan Meta.
- **Lokasi:** peta Leaflet/OpenStreetMap — klik peta, geser penanda, cari alamat (Nominatim), atau pakai lokasi saat ini.
  Di chat, lokasi tampil sebagai peta statis yang dapat dibuka di Google Maps.
- **Kontak (vCard):** pilih dari daftar Kontak (otomatis mengisi `wa_id`) atau isi manual, maks. 10 per pesan. Kartu kontak
  masuk punya tombol **Kirim pesan** dan **Simpan kontak**.
- **Reaksi emoji:** arahkan kursor ke pesan → ikon senyum → emoji cepat atau pemilih lengkap; klik reaksi Anda untuk menghapus.
  Reaksi pelanggan dan reaksi Anda tampil terpisah.
- **Lainnya:** lightbox gambar (navigasi ←/→, unduh, Esc), kamera (webcam di desktop, kamera langsung di HP),
  emoji picker, serta balas dengan kutipan (klik atau geser pesan di layar sentuh).

Media di-cache di `data/media-cache` (maks. 2 GB, 30 hari) sehingga tampil cepat dan mendukung seek; URL media Meta sendiri
hanya berlaku beberapa menit. Semua unggahan tetap melewati `/api/media` dengan validasi MIME dan ukuran sesuai Cloud API.

## Kepuasan pelanggan (CSAT)

Menu **Kepuasan (CSAT)** mengirim survei singkat dan melaporkan hasilnya.

- **Pengiriman:** otomatis saat agen menandai percakapan *Selesai* (opsional juga saat flow menutup percakapan), atau manual dari
  panel info di Inbox. Hanya dikirim selama jendela layanan 24 jam terbuka; secara bawaan hanya bila agen sudah membalas sejak
  survei terakhir, dengan jeda per kontak (24 jam) dan masa berlaku survei (24 jam).
- **Bentuk:** skala 1–5 (pesan daftar) atau 3 tombol (Puas / Biasa saja / Tidak puas), lalu opsional meminta masukan tertulis
  dan mengirim ucapan terima kasih. Jawaban dan masukan tidak membuka kembali percakapan yang sudah selesai dan tidak memicu
  flow maupun auto reply.
- **Laporan:** skor CSAT (% jawaban puas: nilai 4–5, atau "Puas" pada skala 3), rata-rata nilai (dinormalkan ke skala 5),
  tingkat respons, distribusi nilai, tren harian (dengan tampilan tabel), per agen, masukan terbaru, dan riwayat survei.
  Filter rentang tanggal dan agen; ekspor CSV (admin). Agen hanya melihat survei percakapan yang ia tangani.

## Broadcast terjadwal (admin)

Di **Campaign › Campaign baru › Waktu kirim** pilih **Jadwalkan**:

- **Sekali** pada tanggal & jam tertentu, atau **berulang** setiap hari, setiap minggu (pilih hari), atau setiap bulan
  (tanggal yang sama; bulan yang lebih pendek memakai hari terakhir), dengan batas *sampai tanggal* dan/atau *maks. pengiriman*.
- Penerima dihitung ulang dari filter label & opt-in **saat jadwal berjalan**: kontak baru ikut, yang berhenti opt-in tidak dikirimi.
  Tiap kemunculan seri berulang menjadi campaign tersendiri (laporan & CSV per kiriman) yang tertaut ke serinya.
- **Jam kirim** (opsional, mis. 08.00–20.00): di luar jam itu antrean berhenti sementara dan otomatis lanjut.
- Aksi: **Kirim sekarang** (tanpa menggeser jadwal), **Jeda/Lanjutkan seri**, **Hentikan seri**, **Batalkan**.
- Jadwal memakai zona waktu aplikasi (Auto reply › zona waktu). Jadwal yang terlewat saat server mati dijalankan sekali saat server
  hidup; seri berulang lalu melompat ke jadwal berikutnya (tidak mengirim beruntun). Bila template tidak lagi APPROVED atau tidak ada
  kontak yang cocok, kiriman tidak dibuat dan error tampil di daftar campaign.

## Pengingat

Buat dari Inbox (ikon jam di atas chat, atau **Pengingat › Buat** di panel info kontak). Semua pengingat tampil di menu **Pengingat**
(Jatuh tempo · Akan datang · Pesan terjadwal · Riwayat); agen melihat miliknya, admin dapat melihat semua pengguna.

- **Ingatkan saya:** tindak lanjut internal (30 menit, 1 jam, besok 09.00, atau tanggal/jam bebas) dengan catatan. Saat jatuh tempo
  muncul kartu di pojok layar (Buka chat · Selesai · Tunda), bunyi, notifikasi browser, dan — bila diaktifkan di
  Pengaturan › Notifikasi WhatsApp — pesan ke WhatsApp pribadi. Opsional membuka kembali percakapan yang sudah selesai.
  Admin dapat mengatur pengingat untuk pengguna lain.
- **Kirim ke pelanggan:** pesan terjadwal, sekali atau berulang. **Template** APPROVED selalu dapat dikirim (MARKETING hanya ke kontak
  opt-in). **Pesan teks** hanya dikirim bila jendela layanan 24 jam masih terbuka saat jadwal; bila tertutup, Kontaq mengirim
  **template cadangan** (bila dipilih) atau melewatinya — status & alasannya tercatat di riwayat pengingat dan di Log pesan (sumber "Pengingat").
  Pengingat pelanggan yang terlambat lebih dari 6 jam (mis. server mati) dilewati, bukan dikirim terlambat.

## Add-on (admin)

Fitur opsional dikelola di **Pengaturan › Add-on**: **Pasang**, aktif/nonaktifkan (pengaturan tetap tersimpan), atau **Hapus**
(seluruh pengaturan & riwayat add-on dibuang; bisa dipasang lagi). Add-on yang aktif tampil di menu bagian **Add-on**.

### Pengingat absensi

Mengirim template WhatsApp (bawaan `pengingat_absen`) ke pegawai yang **belum presensi datang/pulang**.

- **Sumber data:** presensi hari ini dari `https://ma.pnblk.my.id/api/sikep/absensi-hari-ini` (`belumAbsenDatang` / `belumAbsenPulang`),
  nomor WhatsApp dari `https://pegawai.pnblk.my.id/data_pegawai.json` (`biodata › Nomor Handphone`), dicocokkan lewat NIP. Dari data
  pegawai hanya NIP, nama, jabatan, dan nomor HP yang disimpan (diperbarui tiap jam; salinan terakhir dipakai bila sumber tidak dapat diakses).
  Data presensi yang tanggalnya bukan hari ini ditolak.
- **Variabel template** dipetakan per posisi; bawaan: judul `{{JENIS}}` (DATANG/PULANG), isi `{{nama}}`, `{{jenis}}` (datang/pulang).
  Tersedia juga `{{nip}}` dan `{{tanggal}}`.
- **Jadwal:** beberapa jam kirim per jenis, masing-masing dengan hari (bawaan: datang Sen–Jum 07.45; pulang Sen–Kam 16.05, Jum 16.35),
  plus daftar **hari libur** (tidak dikirim otomatis). Jadwal yang terlewat > 60 menit tidak dikirim; bila API gagal, dicoba lagi tiap 10 menit
  selama masih dalam 60 menit.
- **Per pegawai:** notifikasi on/off (terjadwal hanya ke yang aktif), nomor WhatsApp pengganti, tombol kirim Datang/Pulang.
- **Smart routing (Pengaturan › Cara kirim):** mode *Pintar* (bawaan) mengirim **pesan teks biasa** bila pegawai mengirim/membalas
  pesan dalam 24 jam terakhir (jendela layanan terbuka; diperiksa tepat sebelum tiap pesan dikirim), selain itu **template**.
  Mode *Selalu template* menonaktifkannya. Teks dapat diatur dengan variabel yang sama. Tabel pegawai menandai siapa yang jendelanya
  terbuka, dan detail riwayat menampilkan jalur tiap pesan (Teks/Template). Dalam mode pintar template tetap dibutuhkan untuk
  pegawai yang jendelanya tertutup; bila template belum APPROVED, hanya pegawai dengan jendela terbuka yang dikirimi.
  Pesan teks dapat diberi **tombol link** (pesan interaktif CTA URL: label maks. 20 karakter, teks maks. 1024, URL HTTPS dan boleh
  memuat `{{nip}}`), lengkap dengan **header** dan **footer** teks opsional (masing-masing maks. 60 karakter, boleh memakai variabel).
  Tombol ini tidak berlaku untuk template — tombol pada template diatur saat mengajukan template ke Meta.
  Sebagai ganti tombol link, pesan teks juga bisa memakai **balasan cepat** (maks. 3 tombol, label maks. 20 karakter; WhatsApp tidak
  mengizinkan keduanya dalam satu pesan). Balasan pegawai masuk ke Inbox dan membuka jendela 24 jam.
- **Kirim manual:** pilih pegawai yang belum presensi (data presensi diambil ulang), lalu kirim. Riwayat tiap pengiriman (terkirim/gagal/dilewati)
  ada di tab **Riwayat kirim**, dan setiap pesan di Log pesan (sumber "Pengingat absensi"). Kontak baru diberi label `Pegawai`.

### Ulang tahun pegawai

Kirim ucapan selamat ulang tahun via WhatsApp ke pegawai setiap hari pada jam yang diatur (bawaan 07.30, termasuk akhir pekan).

- **Tanggal lahir** dibaca dari 8 digit awal NIP (YYYYMMDD). Lahir 29 Februari diucapkan 28 Februari pada tahun bukan kabisat.
- **Data pegawai** (nama, jabatan, nomor) diambil dari URL data pegawai yang sama dengan Pengingat absensi, tetapi add-on ini
  berdiri sendiri. Nomor pengganti diatur per pegawai; bila kosong, nomor pengganti dari Pengingat absensi (jika terpasang) dipakai.
- **Jalur kirim** sama dengan Pengingat absensi: mode pintar mengirim teks biasa bila jendela 24 jam terbuka, selain itu template
  (bawaan `ucapan_ulang_tahun`, variabel `{{nama}}`, `{{usia}}`, `{{jabatan}}`, `{{nip}}`, `{{tanggal}}`).
- Ucapan otomatis bisa dimatikan per pegawai. Jadwal yang terlewat karena server mati dijalankan saat server menyala lagi di hari
  yang sama. Memasang add-on atau mengubah jam setelah jam kirim tidak langsung mengirim — gunakan **Kirim ucapan hari ini**.
- Tab **Pegawai** menampilkan ulang tahun mendatang (hari ini, 7 hari, bulan ini); tiap pegawai bisa dikirimi ucapan manual kapan saja
  (mis. ucapan susulan). Riwayat ada di tab **Riwayat kirim** dan Log pesan (sumber "Ulang tahun").

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

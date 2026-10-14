# ⚡ Avenia Workers (OSX)

> **High-Performance Serverless VLESS WebSocket Tunnel & Telegram Bot Control Panel**  
> Deployed globally on Cloudflare's Edge Network (330+ Cities) with **Zero VPS Resource Overhead**.

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![Protocol](https://img.shields.io/badge/Protocol-VLESS%20WS-22c55e?style=for-the-badge)](https://xtls.github.io/)
[![Telegram Bot](https://img.shields.io/badge/Telegram-Bot%20API-24A1DE?style=for-the-badge&logo=telegram&logoColor=white)](https://core.telegram.org/bots)
[![License](https://img.shields.io/badge/License-CC0%201.0-blue?style=for-the-badge)](LICENSE)

---

## 🌟 Fitur Utama (Key Features)

- **100% Serverless & 0% Beban VPS**: Berjalan sepenuhnya di jaringan Anycast Cloudflare Edge tanpa membebani CPU, RAM, atau bandwidth server lokal Anda.
- **Dukungan Bug WS / Fronting Fleksibel**:
  - 🎓 **Bug Kuota Edukasi / Belajar Kemdikbud** (`104.17.3.81`)
  - ⚡ **Cloudflare Clean Anycast Jakarta** (`162.159.138.6`)
  - 📺 **Bug Vidio / Streaming** (`quiz.vidio.com`)
  - 💼 **Bug Zoom Meeting** (`zoom.us`)
  - 🌐 **Domain Resmi Standar** (`cugarete.me`)
- **Protokol Dual-Mode**:
  - **TLS (Port 443)**: Enkripsi aman dengan SNI domain.
  - **NTLS (Port 80)**: Format standar non-TLS bebas handshake overhead.
- **Bot Telegram Interaktif & Manajemen Proxy**:
  - Menu interaktif satu klik (*inline keyboard*).
  - Pengecekan status proxy secara batch (kirim hingga 20 proxy `IP:port`, otomatis diuji latensinya).
  - Generator VLESS acak (*random proxy*) dan pilihan spesifik per server.
  - Tampilan ISP, negara, dan port untuk setiap node.
  - Penghitung statistik request dan penggunaan data real-time.
  - Perintah khusus admin untuk tambah, hapus, dan pembersihan otomatis server mati (`/delvlessdead`).
- **Pool Proxy Terkurasi (40+ Server)**:
  - Meliputi server Asia Tenggara berlatensi rendah: Indonesia (Jakarta), Singapura, Malaysia (Kuala Lumpur), Jepang, Hong Kong, Korea Selatan, serta server internasional (Belanda, Jerman, Inggris, Prancis, US).

---

## 🏗️ Arsitektur Sistem

```
   [ Pengguna / Klien v2rayNG ]
                │
                │  (1) WebSocket melalui Bug IP (misal: 104.17.3.81:80)
                ▼
   [ Cloudflare Global Edge (PoP Jakarta - CGK) ]
                │
                │  (2) Eksekusi CF.js (Serverless Isolation)
                │  (3) Resolusi DNS & Fast Probe Intercept
                ▼
   [ Outbound Proxy Node (Target Egress) ]
   (Singapore AWS / Indonesia CyberNet / Malaysia / dsb.)
                │
                │  (4) Akses Internet Publik
                ▼
       [ Internet Bebas ]
```

---

## 🤖 Panduan Perintah Bot Telegram

Kirim pesan ke bot untuk mengakses fitur-fitur berikut:

### Perintah Pengguna Umum:
| Perintah | Fungsi |
| :--- | :--- |
| `/start` | Membuka menu interaktif dan panduan bot |
| `[kirim IP:port]` | Menguji status & latensi batch hingga 20 proxy sekaligus (dipisahkan baris baru) |
| `/proxy` | Membuat konfigurasi VLESS dari daftar server pilihan |
| `/proxyrandom` | Mengambil 1 server aktif secara acak dan membuatkan VLESS instan siap salin |
| `/listproxy` | Menampilkan seluruh daftar server aktif beserta ISP dan lokasi |
| `/getsub` | Mengambil API link subscription (TLS, NTLS, dan Domain) |
| `/listwildcard` | Melihat daftar wildcard domain yang terdaftar |
| `/addwc [domain]` | Mendaftarkan subdomain / wildcard baru |
| `/delwc [domain]` | Menghapus domain dari daftar wildcard |
| `/donasi` | Menampilkan info rekening dan kanal donasi |
| `/allstatus` | Menguji latensi seluruh server di database secara bersamaan |
| `/data` | Menampilkan statistik total request dan estimasi data terpakai |
| `/bug [IP/Host]` | Mengubah Bug WS aktif langsung dari bot |

### Perintah Khusus Admin:
| Perintah | Fungsi |
| :--- | :--- |
| `/addvless [Negara] [IP:Port] [Nama] [ISP]` | Menambahkan proxy server baru ke database KV |
| `/delvless [ID atau Target]` | Menghapus proxy tertentu dari database |
| `/delvlessdead` | Menguji semua proxy dan otomatis menghapus server yang mati/timeout |
| `/syncproxies` | Mengambil dan memfilter proxy berkecepatan tinggi dari upstream feed |

---

## 🚀 Panduan Instalasi & Deploy

### Prasyarat
1. Node.js (v18+) & `npm`
2. Akun [Cloudflare](https://dash.cloudflare.com/)
3. Bot Telegram dari [@BotFather](https://t.me/botfather)

### Langkah-Langkah Deploy

1. **Clone Repository ini:**
   ```bash
   git clone https://github.com/aryarifki/OSX.git
   cd OSX
   ```

2. **Install Wrangler:**
   ```bash
   npm install -g wrangler
   wrangler login
   ```

3. **Buat Cloudflare KV Namespace:**
   ```bash
   wrangler kv namespace create SERVERS_KV
   ```
   *Salin ID namespace yang muncul ke file `wrangler.json`.*

4. **Konfigurasi `wrangler.json`:**
   Sesuaikan domain, default bug, token bot, dan ID KV Anda:
   ```json
   {
     "name": "cf-tunnel",
     "main": "CF.js",
     "compatibility_date": "2024-09-23",
     "vars": {
       "CUSTOM_DOMAIN": "yourdomain.com",
       "DEFAULT_BUG": "104.17.3.81",
       "BOT_TOKEN": "YOUR_TELEGRAM_BOT_TOKEN"
     },
     "kv_namespaces": [
       {
         "binding": "SERVERS_KV",
         "id": "YOUR_KV_NAMESPACE_ID"
       }
     ]
   }
   ```

5. **Deploy ke Cloudflare Workers:**
   ```bash
   npx wrangler deploy
   ```

6. **Set Webhook Telegram Bot:**
   Buka browser atau gunakan curl:
   ```bash
   curl -F "url=https://yourdomain.com/webhook" https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook
   ```

---

## 📱 Format Link Subscription

Setelah dideploy, link subscription dapat langsung di-import ke aplikasi klien seperti **v2rayNG**, **NekoBox**, **Clash Meta**, atau **Sing-box**:

- **VLESS NTLS (Port 80) — Bug Edukasi:**
  ```text
  https://yourdomain.com/sub/vless/?method=ws&bug=104.17.3.81&port=80
  ```
- **VLESS TLS (Port 443) — Bug Edukasi:**
  ```text
  https://yourdomain.com/sub/vless/?method=ws&bug=104.17.3.81&port=443&tls=true
  ```
- **VLESS TLS (Port 443) — Domain Langsung (WiFi/Reguler):**
  ```text
  https://yourdomain.com/sub/vless/?method=ws&bug=domain&port=443&tls=true
  ```

---

## 📄 Lisensi
Proyek ini didistribusikan di bawah lisensi **CC0 1.0 Universal (Public Domain)**.

# DefenseOps

**Security Operations & Defense Platform**

DefenseOps adalah repository deployment dan automation untuk membangun platform pemantauan keamanan terpusat berbasis **Wazuh**, serta mengintegrasikan event dari endpoint Linux, Nginx/ModSecurity, Docker-PHP, dan sumber log lainnya.

> **Status repository:** Development  
> **Versi Agent Installer Generator:** 1.8.25 (24 November 2026)  
> **Versi Wazuh yang ditargetkan installer:** 4.14.10

Dokumentasi ini disusun berdasarkan file yang tersedia di repository pada 24 November 2026. Fitur yang masih berupa kerangka/TODO disebutkan secara eksplisit dan tidak dianggap sudah berfungsi.

---

## 1. Ruang Lingkup Implementasi

Implementasi yang saat ini tersedia di repository mencakup:

- Deployment single-node Wazuh menggunakan Docker Compose.
- Wazuh Manager, Indexer, dan Dashboard sebagai tiga proyek Compose terpisah.
- Konfigurasi pengumpulan raw JSON archives melalui Filebeat.
- Retensi data log dan arsip.
- Custom Wazuh rules untuk integrasi Brebes-WAF dan Docker-PHP.
- Integrasi GeoIP MaxMind untuk event Brebes-WAF.
- Generator paket instalasi Wazuh Agent untuk endpoint Linux.
- Profil endpoint `Brebes-WAF` dan `Docker-PHP`.
- Discovery konfigurasi Nginx/ModSecurity secara lokal pada endpoint.
- Collector ModSecurity audit log ke format JSONL.
- Collector monitoring Docker-PHP dan event lifecycle Docker.
- File Integrity Monitoring (FIM) aplikasi Docker-PHP menggunakan inotify.
- Dashboard tersimpan dalam format NDJSON untuk diimpor ke Wazuh Dashboard.

Fitur seperti `configure.sh`, `check-server.sh`, dan `healthcheck.sh` masih berupa placeholder dan belum mengimplementasikan fungsi yang dijanjikan oleh namanya.

## 2. Arsitektur

### 2.1 Central Server

```text
                  Linux Endpoints
             ┌──────────┴──────────┐
             │                     │
       Brebes-WAF hosts       Docker-PHP hosts
             │                     │
       Wazuh Agent             Wazuh Agent
       ModSecurity             Docker-PHP collector
       log collector           Docker Events + inotify FIM
             │                     │
             └──────────┬──────────┘
                        │ TCP 1514
                        ▼
               ┌───────────────────┐
               │  Wazuh Manager    │
               │  Rules / Decoders │
               │  Archives         │
               └─────────┬─────────┘
                         │ Filebeat
                         ▼
               ┌───────────────────┐
               │  Wazuh Indexer    │
               │  Alerts / Archives│
               └─────────┬─────────┘
                         │ HTTPS
                         ▼
               ┌───────────────────┐
               │ Wazuh Dashboard   │
               │ Saved Dashboards  │
               └───────────────────┘
```

Ketiga komponen Wazuh berjalan sebagai tiga Docker Compose project terpisah dan bergabung ke Docker network bersama `defenseops-wazuh`.

### 2.2 Endpoint Docker-PHP

Collector Docker-PHP menggunakan **Application Registry** sebagai sumber kebenaran daftar aplikasi yang dimonitor. Collector tidak melakukan pemantauan menyeluruh terhadap semua container atau seluruh direktori aplikasi secara otomatis.

Lokasi registry yang digunakan pada endpoint:

```text
/var/lib/docker-php/monitoring/applications/
```

Data event:

```text
/var/log/defenseops/docker-php-events.json
```

State dan cursor:

```text
/var/lib/defenseops/docker-php/
```

Collector memantau status aplikasi/container, kondisi PHP-FPM, resource, dan event sesuai implementasi collector. Event Docker lifecycle dikumpulkan melalui stream `docker events` dan dibatasi pada container yang terdaftar.

FIM aplikasi dijalankan oleh daemon inotify tersendiri. Ruang lingkup FIM ditentukan oleh registry, termasuk source path dan tambahan writable path jika didefinisikan. Nilai `writable` yang `null`, string kosong, atau array kosong diperlakukan sebagai tidak ada tambahan writable path; source path tetap menjadi cakupan pemantauan sesuai konfigurasi FIM.

### 2.3 Endpoint Brebes-WAF

Generator menghasilkan installer endpoint yang melakukan discovery lokal atas konfigurasi Nginx dan ModSecurity. Discovery ini tidak mengubah konfigurasi Nginx/ModSecurity.

Untuk audit log ModSecurity, installer dapat menyiapkan collector yang membaca audit log dan menormalisasikannya menjadi event JSONL:

```text
/var/log/defenseops/modsecurity-events.json
```

Collector Python `python/defenseops-modsecurity-collector.py` memproses transaksi audit yang lengkap, mengekstrak metadata request/rule, dan melakukan redaksi terhadap pola data sensitif tertentu sebelum event ditulis.

---

## 3. Struktur Repository

```text
DefenseOps/
├── README.md
├── CHANGELOG.md
├── LICENSE
├── COMMERCIAL-LICENSE.md
├── .gitignore
├── scripts/
│   ├── install-requirements.sh
│   ├── generate-agent-installer.sh
│   ├── configure.sh
│   ├── check-server.sh
│   └── healthcheck.sh
├── python/
│   └── defenseops-modsecurity-collector.py
├── agent/
│   └── output/                 # Paket hasil generator; tidak disimpan di Git
├── dashboard/
│   ├── DefenseOps-Global-Security-Overview.ndjson
│   ├── DefenseOps-Docker-PHP-Monitoring.ndjson
│   ├── Docker-PHP-Dashboard.ndjson
│   └── Brebes-WAF-Dashboard.ndjson
├── docs/
│   ├── architecture/
│   ├── deployment/
│   ├── operations/
│   └── security/
├── deployment/
│   ├── docker/
│   └── native/
├── config/
├── backup/
│   └── scripts/                # Snapshot script sebelum perubahan tertentu
├── logo/
├── benchmark/
└── repair-defenseops-structure.ps1
```

Beberapa direktori pada struktur repository masih berupa direktori persiapan atau `.gitkeep`; keberadaannya tidak berarti implementasi di dalamnya sudah tersedia.

---

## 4. Persyaratan Server

### 4.1 Persyaratan yang diperiksa installer

`install-requirements.sh` memeriksa persyaratan berikut:

| Komponen | Persyaratan |
|---|---|
| Sistem operasi | Ubuntu Server 24.04 LTS atau 26.04 LTS |
| Arsitektur | amd64 atau arm64 |
| CPU | Minimum 4 core |
| RAM | Minimum 8 GiB |
| Storage | Minimum 250 GiB pada filesystem `/opt` |
| Hak akses | Root |
| Container runtime | Docker Engine dan Docker Compose plugin |

Angka tersebut merupakan batas minimum yang diperiksa oleh script, bukan sizing yang menjamin kapasitas untuk semua volume log atau jumlah endpoint. Kapasitas produksi harus disesuaikan dengan EPS, retensi, jumlah agent, dan beban indexing.

### 4.2 Komponen yang dipasang

- Docker Engine dan Docker Compose plugin.
- Wazuh Manager.
- Wazuh Indexer.
- Wazuh Dashboard.
- Konfigurasi TLS, kredensial, network, dan volume persisten.
- Konfigurasi Filebeat untuk alerts dan raw archives.
- Custom rules dan integrasi GeoIP yang didukung installer.

Wazuh Docker release default adalah `4.14.10`, dan dapat diubah melalui environment variable `WAZUH_VERSION`.

---

## 5. Instalasi Central Server

Jalankan dari root repository pada Ubuntu Server yang didukung.

### 5.1 Periksa rencana instalasi

```bash
chmod +x scripts/install-requirements.sh
sudo ./scripts/install-requirements.sh --dry-run
```

Mode `--dry-run` memeriksa persyaratan dan menampilkan rencana tanpa menerapkan perubahan instalasi.

### 5.2 Jalankan instalasi

```bash
sudo ./scripts/install-requirements.sh
```

Installer menjalankan persiapan host, Docker, kernel setting, konfigurasi Wazuh, deployment tiga Compose project, konfigurasi Manager/API, Filebeat archives, validasi komunikasi antarkomponen, dan ringkasan hasil instalasi.

Installer dapat mengatur hostname host menjadi `defenseops`. Installer juga mengaktifkan sinkronisasi waktu dan menanyakan apakah timezone perlu diubah ke `Asia/Jakarta`.

### 5.3 Parameter opsional

```bash
# Gunakan versi Wazuh tertentu
sudo WAZUH_VERSION=4.14.10 ./scripts/install-requirements.sh

# Gunakan root instalasi selain default
sudo DEFENSEOPS_ROOT=/srv/defenseops ./scripts/install-requirements.sh

# Tentukan file log installer
sudo LOG_FILE=/var/log/defenseops-install.log ./scripts/install-requirements.sh
```

Default root instalasi adalah `/opt/defenseops`.

### 5.4 Perbaikan Filebeat archives saja

```bash
sudo ./scripts/install-requirements.sh --repair-archives-only
```

Mode ini ditujukan untuk memperbaiki konfigurasi Filebeat archives secara terarah tanpa melakukan redeploy Wazuh.

**Peringatan:** installer normal merupakan alur fresh deployment, bukan general upgrade routine. Jika deployment sudah terdeteksi, installer menghentikan proses untuk melindungi layanan yang sedang berjalan. Opsi `--allow-existing-deployment` memaksa full deployment dan berisiko; jangan gunakan sebagai mekanisme update rutin.

### 5.5 Lokasi dan endpoint layanan

Default yang ditampilkan installer:

| Layanan | Endpoint |
|---|---|
| Wazuh Dashboard | `https://<IP-Manager>:8443` |
| Indexer API | `https://127.0.0.1:9200` |
| Manager API | `https://127.0.0.1:55000` |
| Agent communication | TCP 1514 |
| Agent enrollment | TCP 1515 |
| Syslog | UDP 514 |

Indexer API dan Manager API dibind ke loopback pada konfigurasi installer. Dashboard menggunakan sertifikat self-signed; browser dapat menampilkan peringatan sertifikat sampai sertifikat tepercaya dikonfigurasi.

Kredensial disimpan pada:

```text
/opt/defenseops/secrets/wazuh-credentials.env
```

File tersebut berisi rahasia. Pertahankan permission ketat (installer mengamankan file kredensial) dan jangan commit, membagikan, atau menempelkan isinya ke tiket/chat.

---

## 6. Instalasi Wazuh Agent pada Endpoint

### 6.1 Buat paket installer

Generator dijalankan pada server DefenseOps Manager, bukan pada endpoint:

```bash
chmod +x scripts/generate-agent-installer.sh
sudo ./scripts/generate-agent-installer.sh
```

Opsi generator:

```bash
# Tentukan alamat Manager
sudo ./scripts/generate-agent-installer.sh --manager 15.0.90.3

# Tentukan direktori output
sudo ./scripts/generate-agent-installer.sh --output /tmp/defenseops-agent

# Tampilkan versi generator
./scripts/generate-agent-installer.sh --version

# Bantuan
./scripts/generate-agent-installer.sh --help
```

Generator membuat arsip bundle di `agent/output/` (atau direktori yang dipilih) beserta checksum SHA-256. Direktori output dikecualikan dari Git. Enrollment secret tidak ditanamkan ke paket hasil generator.

### 6.2 Distribusikan dan jalankan pada endpoint

Salin arsip bundle ke endpoint, ekstrak, lalu jalankan `install-agent.sh` sebagai root sesuai petunjuk yang disertakan dalam bundle.

Installer endpoint menyediakan dua profil:

| Profil | Wazuh group | Fungsi utama |
|---|---|---|
| Brebes-WAF | `Brebes-WAF` | Discovery Nginx/ModSecurity dan pengumpulan event terkait |
| Docker-PHP | `docker-php` | Monitoring aplikasi Docker-PHP, Docker lifecycle events, dan FIM registry-scoped |

Installer endpoint melakukan preflight read-only sebelum perubahan paket, konfigurasi, atau layanan. Pemeriksaan meliputi lingkungan OS/systemd, konektivitas Manager, kondisi Wazuh Agent, Docker dan Application Registry untuk profil Docker-PHP, serta path dan konfigurasi sumber log untuk profil terkait.

### 6.3 Perlindungan identitas Agent yang sudah ada

Installer dirancang untuk mendeteksi Agent yang sudah terpasang/terdaftar. Identitas Agent yang sudah enrolled tidak boleh dihapus atau dibuat ulang secara otomatis. `client.keys`, alamat Manager, dan keanggotaan group yang sudah ada dipertahankan pada jalur preservasi; konfigurasi DefenseOps yang diperlukan digabungkan secara terbatas.

Jangan melakukan reset atau re-enrollment manual kecuali ada kebutuhan operasional yang jelas dan prosedur pemulihan identitas telah disiapkan.

---

## 7. Docker-PHP Monitoring

### 7.1 Registry sebagai sumber cakupan

Collector hanya memonitor aplikasi yang tercatat pada Application Registry. Pastikan setiap JSON registry valid dan nama container sesuai dengan container yang benar-benar berjalan.

Contoh pemeriksaan endpoint:

```bash
docker ps
systemctl status defenseops-docker-php-collector.service --no-pager
systemctl status defenseops-docker-php-inotify-fim.service --no-pager
```

Nama unit inotify perlu disesuaikan dengan nama unit yang dipasang oleh bundle apabila berbeda pada rilis yang digunakan.

### 7.2 Event output dan uji lifecycle

```bash
# Pantau output event
sudo tail -f /var/log/defenseops/docker-php-events.json

# Uji restart container yang memang terdaftar di registry
sudo docker restart <nama-container>

# Filter event Docker untuk aplikasi tertentu
sudo grep '"event_source":"docker_events"' \
  /var/log/defenseops/docker-php-events.json
```

Event lifecycle yang ditangani meliputi `start`, `restart`, `die`, `stop`, `oom`, dan `destroy`, dengan penyaringan berdasarkan container yang terdaftar. Collector menggunakan cursor persisten dan mekanisme reconnect/replay untuk membantu pemulihan stream setelah koneksi terputus.

Perhatikan bahwa event `die` tidak selalu berarti insiden. Restart yang disengaja dapat menghasilkan urutan stop/die/start/restart. Interpretasi severity perlu mempertimbangkan exit code, OOM, konteks operasi, dan kebijakan deteksi.

### 7.3 File Integrity Monitoring

FIM Docker-PHP menggunakan daemon inotify terpisah dan database state SQLite. Scope berasal dari Application Registry; source path dan writable path diperlakukan sesuai aturan collector. File/area volatil seperti cache, session, vendor, node_modules, dan direktori pengecualian lain tidak seluruhnya diperlakukan sebagai perubahan kode.

Jangan memperluas scope secara manual ke seluruh filesystem tanpa mempertimbangkan volume event dan dampak performa.

---

## 8. ModSecurity Collector

Script Python:

```text
python/defenseops-modsecurity-collector.py
```

Collector membaca ModSecurity Concurrent Audit Log dan menormalisasi transaksi audit lengkap ke event JSON. Transaksi yang belum memiliki penanda akhir `Z` tidak diproses sebagai transaksi lengkap.

Collector mengambil informasi seperti timestamp, transaction ID, client/server, request method/URI, host, status HTTP, rule ID, message, severity, dan tags jika tersedia. Beberapa pola data sensitif (misalnya password, token, authorization, session, API key, dan cookie value) disamarkan sebelum output.

Jalankan bantuan collector untuk melihat opsi yang tersedia pada versi file:

```bash
python3 python/defenseops-modsecurity-collector.py --help
```

Jangan menganggap redaksi mencakup seluruh kemungkinan data pribadi atau rahasia. Evaluasi output collector dan kebijakan log sebelum digunakan pada lingkungan produksi.

---

## 9. Dashboard dan Data Archives

File dashboard tersimpan di direktori `dashboard/` dalam format NDJSON:

- `DefenseOps-Global-Security-Overview.ndjson`
- `DefenseOps-Docker-PHP-Monitoring.ndjson`
- `Docker-PHP-Dashboard.ndjson`
- `Brebes-WAF-Dashboard.ndjson`

Impor melalui fitur Saved Objects pada Wazuh Dashboard/OpenSearch Dashboards yang sesuai dengan versi deployment. Periksa data view/index pattern, field timestamp, dan filter setelah impor. NDJSON adalah ekspor objek dashboard; file tersebut bukan data event.

Installer mengaktifkan raw JSON archives (`logall_json`) dan Filebeat archives. Pola index archives yang digunakan adalah:

```text
wazuh-archives-4.x-*
```

Arsip raw dan security alerts adalah dua jenis data berbeda. Dashboard yang hanya menggunakan `wazuh-alerts-*` tidak otomatis menampilkan seluruh raw event dari `wazuh-archives-*`.

Retensi yang didefinisikan installer:

| Data | Retensi |
|---|---:|
| Raw logs / archives index | 30 hari |
| Security alerts | 90 hari |
| Manager local compressed archives | 14 hari |

Retensi aktual tetap perlu diverifikasi di Indexer dan Manager setelah deployment. Volume archives dapat tumbuh cepat; pantau disk dan sesuaikan retensi dengan kebutuhan audit serta kapasitas.

---

## 10. GeoIP untuk Brebes-WAF

Installer menyediakan konfigurasi GeoIP berbasis MaxMind untuk database City, Country, dan ASN. File database dipersiapkan dan divalidasi sebelum digunakan, lalu dipasang read-only ke Indexer. Ingest pipeline GeoIP yang disiapkan installer ditujukan untuk event Brebes-WAF; arsip raw tidak menjadi target enrichment tersebut.

Kredensial MaxMind disimpan terpisah di direktori secrets. Updater dijalankan melalui systemd timer setelah konfigurasi pipeline berhasil dipasang. Ketersediaan database bergantung pada akun/izin MaxMind dan keberhasilan proses update.

---

## 11. Operasional dan Troubleshooting

### Status container

```bash
docker ps
docker compose ls
```

### Status service endpoint

```bash
systemctl status wazuh-agent --no-pager
systemctl status defenseops-docker-php-collector.service --no-pager
journalctl -u defenseops-docker-php-collector.service -n 100 --no-pager
```

### Pemeriksaan event lokal

```bash
sudo tail -n 50 /var/log/defenseops/docker-php-events.json
sudo tail -n 50 /var/log/defenseops/modsecurity-events.json
```

File kedua hanya tersedia jika profil/collector ModSecurity telah dipasang dan diaktifkan.

### Pemeriksaan Manager archives

Nama container Manager dapat berbeda menurut nama project Compose. Identifikasi terlebih dahulu:

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
```

Kemudian periksa arsip di dalam container Manager:

```bash
docker exec <manager-container> \
  tail -n 50 /var/ossec/logs/archives/archives.json
```

### Pemeriksaan koneksi Agent

```bash
sudo ss -tnp | grep -E ':(1514|1515)\b'
sudo systemctl status wazuh-agent --no-pager
```

Hindari menempelkan password Indexer, Manager API, enrollment, private key, atau file `client.keys` ke percakapan maupun issue tracker.

---

## 12. Script yang Belum Diimplementasikan

Pada snapshot repository ini, script berikut masih berupa placeholder dan mengembalikan exit code `2`:

- `scripts/check-server.sh`
- `scripts/configure.sh`
- `scripts/healthcheck.sh`

Jangan menjadikannya prosedur operasional sampai implementasinya selesai dan diuji. Pemeriksaan server yang saat ini benar-benar dilakukan adalah bagian dari `install-requirements.sh`.

Dokumentasi rinci pada `docs/architecture/overview.md` dan `docs/deployment/installation.md` juga masih berupa draft singkat; README ini menjadi panduan utama berdasarkan implementasi script yang tersedia.

---

## 13. Backup dan File Generated

- `backup/scripts/` menyimpan snapshot beberapa versi script sebelum perubahan. File backup bukan entrypoint operasional.
- `agent/output/` berisi paket Agent yang dihasilkan dan sengaja dikecualikan dari Git.
- `.structure-backup/` berisi backup hasil script perbaikan struktur repository dan dikecualikan dari Git.
- File rahasia, sertifikat, arsip paket, log, dan hasil benchmark sementara dikecualikan melalui `.gitignore`.

Gunakan script aktif di `scripts/`, bukan salinan di `backup/scripts/`.

---

## 14. Lisensi

Repository menyediakan:

- `LICENSE`
- `COMMERCIAL-LICENSE.md`

Baca kedua dokumen tersebut sebelum menggunakan, memodifikasi, mendistribusikan, atau membangun produk turunan. README tidak menggantikan ketentuan lisensi.

Copyright (c) 2026 Hendrawan Aprillia Ashari, S.T., M.Kom.

---

## 15. Catatan Keamanan

1. Uji perubahan pada lab/staging sebelum production.
2. Batasi akses Dashboard dan port Agent/Enrollment/Syslog dengan firewall.
3. Jangan membuka Indexer API dan Manager API ke jaringan publik; konfigurasi installer membatasi keduanya ke loopback.
4. Lindungi file kredensial dan backup.
5. Verifikasi sertifikat TLS dan ganti sertifikat self-signed jika dibutuhkan.
6. Tinjau custom rules dan active response untuk mengurangi false positive.
7. Terapkan retensi sesuai kapasitas, kebutuhan audit, dan kebijakan organisasi.
8. Pastikan log tidak menyimpan password, token, cookie, atau data pribadi yang tidak diperlukan.
9. Jangan mengasumsikan setiap event lifecycle container merupakan insiden keamanan; lakukan korelasi dan triage.
10. Jangan menjalankan opsi redeploy paksa pada instalasi aktif tanpa backup dan rencana pemulihan.


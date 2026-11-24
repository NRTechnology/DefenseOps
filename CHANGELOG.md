# Changelog

All notable changes to DefenseOps are documented in this file.

Catatan: changelog ini dirangkum dari isi repository dan riwayat Git yang tersedia pada snapshot 24 November 2026. Perubahan refactor yang tidak mengubah perilaku dirangkum, bukan dicatat satu per satu.

## [Unreleased]

- Dokumentasi repository diperbarui agar sesuai dengan implementasi script yang tersedia.
- Ditambahkan panduan deployment Central Server, Agent, Docker-PHP, ModSecurity collector, archives, dashboard, dan troubleshooting.
- Ditegaskan bahwa `check-server.sh`, `configure.sh`, dan `healthcheck.sh` masih placeholder.

## [1.8.25] - 2026-11-24

### Changed
- Versi generator Agent dinaikkan menjadi 1.8.25.
- Validasi Application Registry pada preflight menyelaraskan perlakuan `writable` dengan runtime collector dan inotify FIM.
- `writable: null`, string kosong, atau array kosong diperlakukan sebagai tidak ada tambahan writable path.
- Validasi path writable yang tidak sesuai tetap ditolak.
- Cakupan source path FIM tidak dihilangkan hanya karena writable kosong/null.

## [1.8.24 and development updates] - 2026-11-24

### Added
- Dashboard visualisasi monitoring Docker-PHP.
- Docker lifecycle event collection yang digabungkan ke persistent Docker-PHP runtime collector.
- Pemantauan Docker Events untuk container terdaftar, termasuk event start, restart, die, stop, oom, dan destroy.
- Cursor persisten dan mekanisme reconnect/replay untuk stream Docker Events.
- Pemisahan tanggung jawab pengumpulan lifecycle events dan FIM inotify.

### Changed
- Docker-PHP collector dijalankan sebagai persistent systemd service.
- Snapshot monitoring tetap berjalan periodik (interval lima menit pada implementasi collector).
- Penggunaan Application Registry sebagai sumber scope monitoring.
- Preflight installer endpoint diperluas agar validasi dilakukan sebelum perubahan sistem.

## [1.8.22] - 2026-11-21

### Added
- Heartbeat collector Docker-PHP setelah pengumpulan dan penyimpanan state berhasil.
- Peningkatan logging collector.

## [1.8.21] - 2026-11-21

### Changed
- Pembersihan legacy Syscheck entry Docker-PHP agar pemantauan integritas aplikasi dikelola oleh mekanisme FIM khusus.

## [1.8.20] - 2026-11-19

### Changed
- Pembaruan versi generator dan collector Docker-PHP ke v1.11.0.
- Peningkatan collector dan penyesuaian mekanisme monitoring.

## [1.10.0–1.10.3 collector series] - 2026-11-17

### Added / Changed
- Peningkatan File Integrity Monitoring.
- Validasi writable path dan cakupan monitoring tambahan.
- Peningkatan output ringkasan instalasi dan penanganan error.
- Penyempurnaan monitoring Docker-PHP.

## [1.8.14] - 2026-11-15

### Added
- Discovery aplikasi Docker-PHP dari Application Registry.

## [1.8.13] - 2026-11-15

### Added / Changed
- Custom alert rules untuk Docker-PHP.
- Peningkatan logging dan kemampuan collector Docker-PHP (collector v1.9.1).
- Penyempurnaan ringkasan instalasi Agent.

## [1.8.12] - 2026-11-15

### Changed
- Peningkatan fungsionalitas dan logging Docker-PHP collector.

## [1.8.10] - 2026-11-14

### Changed
- Peningkatan perilaku installer untuk Wazuh Agent yang sudah terpasang atau sudah enrolled.

## [1.8.9] - 2026-11-14

### Changed
- Penyempurnaan konfigurasi instalasi systemd unit collector.

## [1.8.6] - 2026-11-13

### Changed
- Pembaruan versi installer dan perbaikan perilaku instalasi endpoint.

## [1.8.4] - 2026-11-10

### Changed
- Pembaruan versi installer Agent.

## [1.8.2] - 2026-11-10

### Changed
- Pembaruan versi installer Agent dan penyempurnaan penetapan group berdasarkan profil endpoint.

## [1.8.1] - 2026-11-10

### Changed
- Penyesuaian assignment Wazuh group berdasarkan profil endpoint.

## [1.7.0] - 2026-11-09

### Added
- Integrasi ModSecurity audit collector pada paket installer Agent.

## [1.6.0] - 2026-11-09

### Changed
- Penyempurnaan discovery konfigurasi Nginx/ModSecurity pada endpoint.

## [1.5.0] - 2026-11-09

### Changed
- Penyempurnaan proses re-enrollment dan penanganan Agent yang telah terpasang.

## [1.4.1] - 2026-11-08

### Changed
- Penyempurnaan format log dan versioning generator.

## [1.4.0] - 2026-11-08

### Changed
- Penyempurnaan enrollment dan logging Agent.

## [1.3.8] - 2026-11-08

### Changed
- Penyempurnaan verifikasi dan pemformatan konfigurasi access log.

## [1.3.7] - 2026-11-08

### Changed
- Peningkatan parser konfigurasi Nginx dan verifikasi access log.

## [1.0.0 development baseline] - 2026-11-08

### Added
- Generator paket Wazuh Agent DefenseOps.
- Installer Central Server berbasis Docker Compose untuk Wazuh.
- Pemisahan deployment Manager, Indexer, dan Dashboard.
- Konfigurasi Filebeat archives dan opsi perbaikan archives terarah.
- Pembuatan dan verifikasi Wazuh Agent groups `Brebes-WAF` dan `docker-php`.
- Custom rules Brebes-WAF (rule ID 100500–100506).
- Custom rules Docker-PHP (rule ID 100600–100603, 100610, 100620–100621).
- Integrasi GeoIP MaxMind untuk event Brebes-WAF.
- Dashboard Global Security Overview dan dashboard terkait Brebes-WAF/Docker-PHP.

---

## Catatan Versi

- `1.8.x` adalah versi **Agent Installer Generator**, bukan versi DefenseOps Central Server secara keseluruhan.
- `1.10.x`, `1.11.x`, dan `1.14.x` pada riwayat pengembangan merujuk pada versi internal Docker-PHP collector pada tahap-tahap tertentu.
- Versi Wazuh yang ditargetkan oleh script pada snapshot ini adalah `4.14.10`.
- Changelog ini tidak mengklaim seluruh roadmap atau direktori yang masih kosong sebagai fitur yang sudah tersedia.

# CVEHunterX 🔎⚡  
**Advanced Bug Bounty Research Platform — The Ultimate CVE Weaponizer**

> Edukasi & riset keamanan siber. Gunakan **hanya di aset Anda sendiri** atau dengan izin tertulis. 🙏

---

## ✨ Fitur Utama
- **Advanced CVE Discovery (NVD 2.0)** → ambil CVE terbaru lengkap dengan CVSS, severity, products, description, filter skor, dan keyword.  
- **GitHub PoC Hunter** → cari PoC repo untuk CVE tertentu dengan GitHub Search API (support token).  
- **Shodan Intelligence** → profil host/IP (org, OS, ports, vulns) dengan Shodan API key.  
- **Advanced Recon Suite**:
  - Subdomain Enumeration (wordlist + crt.sh)
  - Port Scanner + Banner Grab
  - Technology Stack Detection (WP, Laravel, React, dsb.)
  - Security Headers & Domain Intel
- **Vulnerability Timeline** → statistik tahunan jumlah CVE & rata-rata skor.  
- **Auto Report Generator** → HTML + JSON dengan timestamp.  
- **SQLite Caching** → cache CVE & target summary di `cve.db`.  
- **Interactive TUI Mode + CLI Mode** → bisa interaktif (menu) atau sekali jalan via argumen.

---

## 📦 Instalasi

### Persyaratan
- Python 3.9+
- Internet (akses NVD, GitHub, crt.sh; Shodan opsional)

### Dependensi
```bash
pip install requests tabulate dnspython python-whois pyyaml beautifulsoup4 aiohttp shodan
```

---

## ⚙️ Konfigurasi API
Saat pertama kali jalan, script membuat `config.yaml` default:
```yaml
shodan_api_key: ""
github_token: ""
user_agents:
  - Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  - Mozilla/5.0 (X11; Linux x86_64)
wordlists:
  subdomains: [www, api, admin, dev, staging]
  endpoints: ["/admin", "/.env", "/config", "/debug", "/api/v1"]
```
- Isi `shodan_api_key` untuk Shodan Intelligence.  
- Isi `github_token` agar hunting PoC tidak kena rate-limit.

---

## 🚀 Cara Menjalankan

### Mode Interaktif
```bash
python cve_hunter.py
```
Akan muncul menu:
1. CVE Discovery
2. CVE Deep Analysis + PoCs
3. Full Recon
4. Subdomain Enumeration
5. Port Scanner
6. Technology Detection
7. Shodan Intelligence
8. Vulnerability Stats
9. Config
0. Exit

### Mode CLI
- CVE terbaru 7 hari terakhir (score ≥ 7.5):
```bash
python cve_hunter.py --recent 7 --score 7.5
```
- CVE + PoC detail:
```bash
python cve_hunter.py --details CVE-2024-1234 --report
```
- Full Recon domain:
```bash
python cve_hunter.py --recon example.com --report
```
- Subdomain enum:
```bash
python cve_hunter.py --subdomains target.com
```
- Portscan:
```bash
python cve_hunter.py --portscan target.com
```
- Tech stack detect:
```bash
python cve_hunter.py --tech target.com
```
- Shodan intel:
```bash
python cve_hunter.py --shodan target.com
```

---

## 📂 Output
- `Hunter_report_<type>_<timestamp>.html` → laporan HTML.
- `Hunter_data_<type>_<timestamp>.json` → backup JSON.
- `cve.db` → cache CVE & summary target.

---

## 🧭 Alur Rekomendasi
1. Discovery CVE global (`--recent`, `--score`).
2. Recon domain target (`--recon`).
3. Deep dive CVE detail + PoC.
4. Generate report (`--report`).

---

## 🛠️ Troubleshooting
- **Module not found** → pastikan sudah `pip install` semua dependensi.
- **GitHub PoC kosong** → tambahkan `github_token`.
- **Shodan error** → cek koneksi & API key.
- **CVE kosong** → longgarkan filter `--score` atau tambah `--recent`.

---

## ⚖️ Legal Disclaimer
Gunakan hanya untuk:
- ✅ Edukasi & audit internal.
- ✅ Pentesting dengan izin tertulis.
- ✅ Responsible disclosure.

🚫 Penyalahgunaan = ilegal.

---

## ❤️ Kredit
- **CVEHunterX** by r00tH3x — basis kode & ide.


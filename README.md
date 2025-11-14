# Malicious Web Detector (MWD)

MWD (Malicious Web Detector) adalah tool Python untuk menganalisis keamanan sebuah website melalui berbagai teknik pasif, heuristik, dan integrasi API eksternal.
Tool ini mampu mendeteksi indikasi phishing, malicious behavior, misconfiguration, hingga reputasi domain/IP.

## Fitur Utama

- MWD melakukan beberapa analisis berikut:

🔍 Analisis URL & Domain

- Validasi URL otomatis
- Deteksi punycode (indikasi domain tiruan)
- Entropy domain (indikasi domain acak/berbahaya)
- Domain age (baru didaftarkan → risiko lebih tinggi)

🌐 Analisis DNS

- Lookup DNS: A, AAAA, MX, NS, CNAME, dan TXT
- Deteksi anomali seperti tidak adanya A record
- Parsing nameserver & MX untuk indikasi suspicious domain

🧾 WHOIS & RDAP

- Informasi domain: registrar, creation date, expiration date
- Fallback otomatis ke RDAP jika WHOIS gagal
- Menyimpan raw WHOIS/RDAP untuk analisis lanjutan

🔒 Analisis TLS/SSL
- Certificate issuer, valid-from & valid-until
- Deteksi sertifikat error, expired, atau hampir kedaluwarsa

🌐 Analisis HTTP

Fetch halaman dengan User-Agent custom

Ambil:

- Status code
- Redirect chain
- Header HTTP
- Deteksi header security yang hilang:
- X-Frame-Options
- Content-Security-Policy

🧪 Analisis HTML/JS

- Heuristik untuk mencari indikasi web berbahaya:
- eval(), document.write(), unescape(), atob(), dll.
- Base64 berukuran besar
- Hidden iframe
- Hex obfuscation
- Banyak script tag

🧱 Integrasi API (Opsional)

Jika memiliki API key:

- VirusTotal URL scanning
- VirusTotal IP reputation
- AbuseIPDB IP reputation

🔌 Port Scan (Ringan & Non-Invasive)

- Port umum:
21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5900

🧮 Skoring Risiko

Menghasilkan:

- Score 0–100
- Verdict: clean, suspicious, atau malicious
- Daftar reason yang menjelaskan penyebab skornya

## Installation

1. Clone Repository

```bash
git clone https://github.com/valeriankaleb/Tools-mal-web-detection-python.git
cd Tools-mal-web-detection-python
```

2. Install Dependencies
```bash
pip install requests dnspython python-whois tldextract validators
```

## Usage

```python
python malicious_web_detector.py --url "http://example.com" --vt-api-key VIRUSTOTAL_KEY --abuse-api-key ABUSEIPDB_KEY
```

# ⚠️ Legal & Ethical Notice

Tool ini dibuat untuk tujuan keamanan defensif dan pembelajaran.

❗ Dilarang keras:

- Memindai website tanpa izin pemilik
- Menggunakan tool ini untuk aktivitas malicios atau ilegal

❗ Beberapa modul (WHOIS, API query) dapat memicu banyak request → gunakan secara bijak.

Please make sure to update tests as appropriate.

# Screenshot Output
![Demo 1](/img/1.png)
![Demo 2](/img/2.png)
![Demo 3](/img/3.png)
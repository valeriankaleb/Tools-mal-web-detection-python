"""
Malicious Web Detector - Python

Fitur:
- Validasi URL
- DNS lookup (A, AAAA, MX, NS)
- WHOIS (domain creation/expiry)
- Resolve IP & ASN lookup (optional placeholder)
- TLS/SSL certificate inspection
- HTTP headers inspection (server, x-frame-options, content-security-policy)
- Simple port check (connect to common ports) — non-invasive
- HTML / JS heuristics (presence of eval, document.write, long hex strings, base64 blobs, hidden iframes/forms)
- Domain heuristics (entropy, length, punycode, age)
- Optional integrations with APIs: VirusTotal, AbuseIPDB, Google Safe Browsing (API keys required, placeholders provided)
- Scoring engine that outputs a simple risk score and explanation list

Cara pakai (contoh):
    python malicious_web_detector.py --url "http://example.com" --vt-api-key YOUR_KEY --abuse-api-key YOUR_KEY

Catatan hukum & etika:
- Tool ini dibuat untuk tujuan keamanan defensif (deteksi/multi-analisis) dan pembelajaran.
- Jangan memindai atau menyerang situs yang bukan milik Anda atau tanpa izin eksplisit dari pemilik.
- Beberapa pemeriksaan (port scan, WHOIS) dapat menghasilkan banyak permintaan ke pihak ketiga — gunakan secara bijak.

Dependencies (pip):
    pip install requests dnspython python-whois tldextract validators

Beberapa fitur memerlukan API keys (VirusTotal, AbuseIPDB, Google Safe Browsing). Jika tidak punya, tool masih bisa menjalankan heuristik lokal.

"""

import argparse
import socket
import ssl
import re
import requests
import whois
import time
import math
import base64
import tldextract
import validators
import dns.resolver
from datetime import datetime

# -------------------- Utilities --------------------

def entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    ent = - sum([p * math.log(p, 2) for p in prob])
    return ent


def is_punycode(domain: str) -> bool:
    return domain.startswith('xn--') or 'xn--' in domain


# -------------------- Network / DNS / WHOIS / SSL --------------------

def resolve_dns(domain: str):
    records = {}
    types = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT']
    resolver = dns.resolver.Resolver()
    for t in types:
        try:
            answers = resolver.resolve(domain, t, lifetime=5)
            records[t] = [str(r.to_text()) for r in answers]
        except Exception:
            records[t] = []
    return records


def whois_info(domain: str):
    """
    Robust whois_info:
    - coba python-whois (whois.whois) bila tersedia
    - jika tidak, fallback ke RDAP (rdap.org) via HTTP
    - mengembalikan dict dengan fields: domain_name, creation_date, expiration_date, registrar, org/emails, whois_raw
    """
    # Try python-whois first
    try:
        import whois as pywhois
        if hasattr(pywhois, 'whois'):
            w = pywhois.whois(domain)
            return {
                'domain_name': getattr(w, 'domain_name', None),
                'creation_date': getattr(w, 'creation_date', None),
                'expiration_date': getattr(w, 'expiration_date', None),
                'registrar': getattr(w, 'registrar', None),
                'org': getattr(w, 'org', None) or getattr(w, 'organization', None),
                'emails': getattr(w, 'emails', None),
                'name': getattr(w, 'name', None),
                'whois_raw': str(w)
            }
    except Exception:
        # ignore and fallback to RDAP
        pass

    # Fallback: RDAP via rdap.org (no extra package required besides requests)
    try:
        rdap_url = f'https://rdap.org/domain/{domain}'
        r = requests.get(rdap_url, timeout=10)
        if r.ok:
            j = r.json()
            # try to extract creation/expiration
            creation = None
            expiration = None
            events = j.get('events', []) or j.get('event', []) or []
            # events may contain objects with eventAction and eventDate
            dates = []
            for ev in events:
                dt = ev.get('eventDate') or ev.get('date')
                if dt:
                    dates.append(dt)
            if dates:
                # best-effort: take earliest as creation
                creation = min(dates)
            # registrar
            registrar = j.get('registrar') or j.get('registrarName') or None
            # nameservers
            nameservers = []
            for ns in j.get('nameservers', []) or []:
                if isinstance(ns, dict):
                    nameservers.append(ns.get('ldhName') or ns.get('handle'))
                else:
                    nameservers.append(ns)
            return {
                'domain_name': j.get('ldhName', domain),
                'creation_date': creation,
                'expiration_date': expiration,
                'registrar': registrar,
                'nameservers': nameservers,
                'org': None,
                'emails': None,
                'whois_raw': r.text
            }
        else:
            return {'error': f'rdap_failed_status_{r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


def get_ssl_info(hostname: str, port: int = 443, timeout=5):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # getpeercert returns dict with subject, subjectAltName, notBefore, notAfter
                return cert
    except Exception as e:
        return {'error': str(e)}


# -------------------- HTTP / HTML Analysis --------------------

def fetch_url(url: str, timeout=10):
    headers = {'User-Agent': 'MaliciousDetector/1.0 (+https://example.invalid)'}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return {
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'final_url': resp.url,
            'history': [h.status_code for h in resp.history],
            'text': resp.text[:200000]  # cap size
        }
    except Exception as e:
        return {'error': str(e)}


def analyze_html(html: str):
    findings = []
    if not html:
        return findings

    # suspicious functions
    suspicious_patterns = [r"\beval\s*\(", r"document\.write\(", r"unescape\(", r"atob\(", r"fromCharCode\("]
    for p in suspicious_patterns:
        if re.search(p, html, flags=re.IGNORECASE):
            findings.append(f"suspicious_js_pattern: {p}")

    # long base64 blobs
    base64_matches = re.findall(r"[A-Za-z0-9+/]{100,}={0,2}", html)
    if base64_matches:
        findings.append(f"base64_blobs_count={len(base64_matches)}")

    # hidden iframes/forms
    hidden_iframes = re.findall(r"<iframe[^>]+(display:\s*none|width=['\"]0|height=['\"]0)[^>]*>", html, flags=re.IGNORECASE)
    if hidden_iframes:
        findings.append(f"hidden_iframes={len(hidden_iframes)}")

    # large obfuscated hex strings
    hex_matches = re.findall(r"(?:\\x[a-fA-F0-9]{2}){20,}", html)
    if hex_matches:
        findings.append(f"hex_obfuscation_count={len(hex_matches)}")

    # number of script tags
    script_tags = re.findall(r"<script[^>]*>", html, flags=re.IGNORECASE)
    if len(script_tags) > 10:
        findings.append(f"many_script_tags={len(script_tags)}")

    return findings


# -------------------- Blacklist / External APIs (placeholders) --------------------

def check_virus_total_ip(ip: str, api_key: str):
    """Placeholder: query VirusTotal IP reputation. Requires API key."""
    if not api_key:
        return {'skipped': True}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {'x-apikey': api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        return r.json()
    except Exception as e:
        return {'error': str(e)}


def check_virus_total_url(url_to_check: str, api_key: str):
    if not api_key:
        return {'skipped': True}
    url = 'https://www.virustotal.com/api/v3/urls'
    headers = {'x-apikey': api_key}
    try:
        r = requests.post(url, data={'url': url_to_check}, headers=headers, timeout=10)
        return r.json()
    except Exception as e:
        return {'error': str(e)}


def check_abuse_ip(ip: str, api_key: str):
    if not api_key:
        return {'skipped': True}
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'ipAddress': ip}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        return r.json()
    except Exception as e:
        return {'error': str(e)}


# -------------------- Simple Port Check --------------------

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,3389,5900]

def scan_ports(host: str, ports=COMMON_PORTS, timeout=1):
    open_ports = []
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                open_ports.append(p)
        except Exception:
            pass
    return open_ports


# -------------------- Heuristic Scoring --------------------

def score_results(domain, ip_list, dns_records, whois_res, ssl_info, http_res, html_findings, vt_data_ip=None, vt_data_url=None, abuse_ip_data=None):
    score = 0
    reasons = []

    # Domain heuristics
    ext = tldextract.extract(domain)
    dom = ext.domain
    sub = ext.subdomain
    full_domain = ".".join([p for p in [sub, dom, ext.suffix] if p])

    if is_punycode(domain):
        score += 20
        reasons.append('punycode_domain')

    dom_entropy = entropy(dom)
    if dom_entropy > 3.5 or len(dom) > 25:
        score += 15
        reasons.append(f'domain_entropy_or_length(entropy={dom_entropy:.2f},len={len(dom)})')

    # WHOIS age
    try:
        cd = whois_res.get('creation_date')
        if cd and isinstance(cd, (list, tuple)):
            cd = cd[0]
        if cd:
            age_days = (datetime.utcnow() - cd).days
            if age_days < 30:
                score += 20
                reasons.append(f'domain_new(age_days={age_days})')
            elif age_days < 365:
                score += 5
                reasons.append(f'domain_relatively_new(age_days={age_days})')
    except Exception:
        pass

    # DNS anomalies
    if not dns_records.get('A'):
        score += 20
        reasons.append('no_A_record')

    # SSL checks
    if isinstance(ssl_info, dict) and 'error' in ssl_info:
        score += 10
        reasons.append('ssl_error')
    else:
        notAfter = ssl_info.get('notAfter')
        if notAfter:
            try:
                exp = datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z')
                if (exp - datetime.utcnow()).days < 30:
                    score += 5
                    reasons.append('ssl_expires_soon')
            except Exception:
                pass

    # HTTP headers
    if isinstance(http_res, dict) and http_res.get('headers'):
        h = http_res['headers']
        if 'x-frame-options' not in {k.lower() for k in h.keys()}:
            score += 3
            reasons.append('missing_x_frame_options')
        if 'content-security-policy' not in {k.lower() for k in h.keys()}:
            score += 3
            reasons.append('missing_csp')

    # HTML findings
    score += len(html_findings) * 5
    reasons += html_findings

    # Blacklist data
    if vt_data_ip and isinstance(vt_data_ip, dict):
        # naive: check if VT reports malicious counts (structure depends on API)
        if vt_data_ip.get('malicious'):
            score += 50
            reasons.append('virustotal_ip_malicious')
    if abuse_ip_data and isinstance(abuse_ip_data, dict):
        if abuse_ip_data.get('data') and abuse_ip_data['data'].get('abuseConfidenceScore', 0) > 50:
            score += 40
            reasons.append('abuseipdb_high_confidence')

    # final clamp
    score = min(score, 100)

    verdict = 'clean'
    if score >= 70:
        verdict = 'malicious'
    elif score >= 30:
        verdict = 'suspicious'

    return {'score': score, 'verdict': verdict, 'reasons': reasons}


# -------------------- Main orchestration --------------------

def analyze_target(url: str, vt_api_key=None, abuse_api_key=None, do_ports=False):
    report = {'url': url, 'timestamp': datetime.utcnow().isoformat()}

    if not validators.url(url):
        # coba tambahkan skema
        if validators.url('http://' + url):
            url = 'http://' + url
        else:
            return {'error': 'invalid_url'}

    report['normalized_url'] = url

    parsed = tldextract.extract(url)
    domain = parsed.registered_domain or parsed.domain + '.' + parsed.suffix
    report['domain'] = domain

    # DNS lookup
    dns_records = resolve_dns(domain)
    report['dns'] = dns_records

    # WHOIS info
    who = whois_info(domain)
    report['whois'] = who

    # Ambil IP dari A record
    ip_list = []
    for a in dns_records.get('A', []):
        ip = a.split()[0]
        ip_list.append(ip)
    report['ips'] = ip_list

    # SSL info (fixed: aman dari label kosong)
    ssl_info = None
    if url.startswith('https') or ip_list:
        # pastikan hostname valid, tanpa label kosong
        parts = [p for p in [parsed.subdomain, parsed.domain, parsed.suffix] if p]
        target_host = ".".join(parts)
        try:
            ssl_info = get_ssl_info(target_host)
        except Exception as e:
            ssl_info = {'error': str(e)}
    report['ssl'] = ssl_info

    # HTTP fetch dan HTML analisis
    http_res = fetch_url(url)
    report['http'] = {k: v for k, v in http_res.items() if k != 'text'}
    html_text = http_res.get('text') if isinstance(http_res, dict) else ''
    html_findings = analyze_html(html_text)
    report['html_findings'] = html_findings

    # Cek eksternal (opsional)
    vt_ip = None
    vt_url = None
    abuse = None
    if ip_list and vt_api_key:
        vt_ip = check_virus_total_ip(ip_list[0], vt_api_key)
    if vt_api_key:
        vt_url = check_virus_total_url(url, vt_api_key)
    if ip_list and abuse_api_key:
        abuse = check_abuse_ip(ip_list[0], abuse_api_key)

    report['vt_ip'] = vt_ip
    report['vt_url'] = vt_url
    report['abuseipdb'] = abuse

    # Port scan (opsional)
    if do_ports and ip_list:
        report['open_ports'] = scan_ports(ip_list[0])

    # Skoring akhir
    score = score_results(domain, ip_list, dns_records, who, ssl_info, http_res, html_findings, vt_ip, vt_url, abuse)
    report['score'] = score

    return report


# -------------------- CLI --------------------

def main():
    parser = argparse.ArgumentParser(description='Malicious Web Detector')
    parser.add_argument('--url', required=True, help='Target URL (include scheme)')
    parser.add_argument('--vt-api-key', help='VirusTotal API key (optional)')
    parser.add_argument('--abuse-api-key', help='AbuseIPDB API key (optional)')
    parser.add_argument('--ports', action='store_true', help='Do a lightweight port connect scan')
    args = parser.parse_args()

    report = analyze_target(args.url, vt_api_key=args.vt_api_key, abuse_api_key=args.abuse_api_key, do_ports=args.ports)

    import json
    print(json.dumps(report, indent=2, default=str))


if __name__ == '__main__':
    main()
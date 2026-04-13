# 🔍 Recon Toolkit

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/github/license/liketosweep/recon-toolkit?style=flat-square)
![Last Commit](https://img.shields.io/github/last-commit/liketosweep/recon-toolkit?style=flat-square)
![Stars](https://img.shields.io/github/stars/liketosweep/recon-toolkit?style=flat-square)
![Issues](https://img.shields.io/github/issues/liketosweep/recon-toolkit?style=flat-square)
![CI](https://img.shields.io/github/actions/workflow/status/liketosweep/recon-toolkit/ci.yml?style=flat-square&label=CI)

**A modular, async web reconnaissance framework for bug bounty hunters and penetration testers.**

Passive subdomain discovery · DNS enumeration · TLS certificate analysis · Tech fingerprinting · Wayback Machine mining · Async port scanning · Vulnerability checks · HTML reports

[Installation](#-installation) · [Usage](#-usage) · [Modules](#-modules) · [Reports](#-html-reports) · [Docker](#-docker) · [Roadmap](#-roadmap)

</div>

---

## 📸 Demo

```bash
python cli.py full reddit.com --output reports/reddit.html
```

![Full Pipeline Output](assets/sample%20output.gif)

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🌐 **Subdomain Enumeration** | Passive discovery via crt.sh + HackerTarget, then brute-force DNS resolution |
| 📡 **DNS Recon** | Queries A, AAAA, MX, NS, TXT, CNAME, SOA — detects missing SPF/DMARC/DKIM |
| 🔒 **SSL/TLS Inspector** | Cert expiry, issuer, Subject Alternative Names (leaks internal hosts) |
| 🛡 **HTTP Header Analysis** | Security header audit with a 0–100% score, cookie flags, info disclosure |
| ⚙️ **Tech Stack Detection** | Fingerprints 30+ technologies — CMS, frameworks, CDNs, WAFs |
| 🚨 **Vulnerability Checks** | Open redirect, CORS misconfiguration, clickjacking, reflected input |
| 📼 **Wayback Machine Recon** | Mines CDX API for archived API endpoints, admin panels, config files |
| 🔌 **Port Scanner** | Async TCP scan of 60+ common ports with high-risk service flagging |
| 📁 **Directory Discovery** | Fully async brute-force — 50× faster than synchronous alternatives |
| 📊 **HTML / JSON Reports** | Dark-themed professional report with summary dashboard |

---

## 🚀 Installation

```bash
git clone https://github.com/liketosweep/recon-toolkit.git
cd recon-toolkit
pip install -r requirements.txt
```

**Download wordlists** (required for subdomain and directory modules):

```bash
mkdir -p wordlists

curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
     -o wordlists/subdomains.txt

curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
     -o wordlists/directories.txt
```

---

## 🛠️ Usage

### Run the full pipeline

```bash
python cli.py full example.com
```

### Save report as HTML or JSON

```bash
python cli.py full example.com --output reports/example.html
python cli.py full example.com --output reports/example.json
```

### Skip specific modules

```bash
python cli.py full example.com --skip wayback --skip ports
```

### Run individual modules

```bash
python cli.py subdomains example.com
python cli.py dns        example.com
python cli.py ssl        example.com
python cli.py analyze    example.com
python cli.py tech       example.com
python cli.py vulncheck  example.com
python cli.py waybackrecon example.com
python cli.py portscan   example.com
python cli.py directories example.com
```

### Custom options

```bash
# Custom wordlist + thread count
python cli.py subdomains example.com --wordlist /path/to/list.txt --threads 50

# Higher async concurrency for directory scan
python cli.py directories example.com --concurrency 100

# Limit Wayback results
python cli.py waybackrecon example.com --limit 500
```

---

## 📦 Modules

### 🌐 Subdomain Enumeration
Runs in two phases:
1. **Passive** — queries crt.sh (certificate transparency logs) and HackerTarget API. No wordlist needed. Finds real subdomains that have been issued SSL certs or publicly crawled.
2. **Active** — DNS brute-force using your wordlist with concurrent threading.

Both phases are combined and deduplicated in the final output.

### 📡 DNS Recon
Queries all major record types (A, AAAA, MX, NS, TXT, CNAME, SOA) and then separately checks SPF, DMARC, and DKIM records. Missing email security records are a commonly valid bug bounty finding — misconfigured SPF/DMARC allows domain spoofing.

### 🔒 SSL/TLS Inspector
Connects directly over TLS and inspects the raw certificate. The Subject Alternative Names (SANs) field often reveals staging, internal, or previously public subdomains that wouldn't appear in passive enumeration. Also shows expiry countdown with colour-coded urgency.

### 🛡 HTTP Header Analysis
Checks for 9 security headers and produces a 0–100% score. Also inspects cookie attributes (`Secure`, `HttpOnly`, `SameSite`) and flags headers that disclose backend technology (`Server`, `X-Powered-By`, `X-AspNet-Version`).

### ⚙️ Technology Detection
Fingerprints 30+ technologies through a pattern database of HTTP headers, HTML body signatures, and cookie names. No external API needed. Covers CMS platforms, backend frameworks, JS frameworks, web servers, CDNs, and WAFs.

### 🚨 Vulnerability Checks
Runs lightweight misconfiguration probes:
- **Open Redirect** — tests 4 common redirect parameter patterns
- **Reflected Input** — tests 3 parameter names with a unique probe string
- **CORS Misconfiguration** — checks for wildcard or reflected origin with `credentials: true`
- **Clickjacking** — verifies `X-Frame-Options` or `frame-ancestors` CSP directive
- **Dangerous HTTP Methods** — probes PUT, DELETE, TRACE, CONNECT, PATCH
- **security.txt** — checks for a responsible disclosure policy

### 📼 Wayback Machine Recon
Uses the Wayback CDX API (no auth required) to retrieve archived URLs. Automatically categorises them into: API endpoints, admin panels, config/backup files, JavaScript files, login pages, and sensitive paths.

### 🔌 Port Scanner
Async TCP connect scan using `asyncio.open_connection`. Scans 60+ common ports concurrently. Flags high-risk services that should never be internet-facing (Redis, MongoDB, Docker API, Elasticsearch, Kubernetes, etc.).

### 📁 Directory Discovery
Rewritten from synchronous `requests` to fully async `aiohttp` with configurable concurrency. Includes a live progress bar. On a 4,000-word wordlist: ~4 seconds async vs. ~400 seconds synchronous.

---

## 📊 HTML Reports

Generate a professional dark-themed HTML report with a full summary dashboard:

```bash
python cli.py full example.com --output reports/example.html
```

The report includes:
- Stat cards (subdomain count, port count, vuln count, security score)
- Collapsible sections for every module
- Colour-coded severity badges
- Clickable subdomain / URL links
- Security header progress bar

---

## ⚙️ Configuration

Edit `config.yaml` to set your defaults:

```yaml
threads: 20           # Subdomain brute-force threads
timeout: 5            # Request timeout (seconds)
concurrency: 50       # Async concurrency for directory/port scan

wordlists:
  subdomains: wordlists/subdomains.txt
  directories: wordlists/directories.txt

api_keys:
  shodan: ""          # Optional — adds passive port intel
  virustotal: ""      # Optional — adds passive subdomain sources

output:
  default_format: json
  output_dir: reports
```

---

## 🐳 Docker

Build and run without installing anything locally:

```bash
# Build
docker build -t recon-toolkit .

# Run full pipeline
docker run --rm recon-toolkit full example.com

# Save report to host
docker run --rm -v $(pwd)/reports:/app/reports \
  recon-toolkit full example.com --output reports/example.html
```

---

## 📁 Project Structure

```
recon-toolkit/
├── cli.py                    # Unified CLI entry point (Click)
├── config.yaml               # User configuration
├── requirements.txt
├── Dockerfile
│
├── recon/                    # Recon modules
│   ├── subdomain.py          # Passive + brute-force subdomain enum
│   ├── dns_recon.py          # DNS records + email security analysis
│   ├── ssl_info.py           # TLS certificate inspection
│   ├── http_analyzer.py      # HTTP header audit
│   ├── tech_detect.py        # Technology fingerprinting
│   ├── vuln_checker.py       # Misconfiguration checks
│   ├── wayback.py            # Wayback Machine CDX mining
│   ├── port_scanner.py       # Async TCP port scanner
│   └── directory.py          # Async directory brute-force
│
├── core/
│   ├── config.py             # Config loader (YAML → dict)
│   └── reporter.py           # JSON / TXT / HTML report generator
│
├── templates/
│   └── report.html           # Jinja2 HTML report template
│
├── wordlists/                # Populated via setup commands
│   ├── subdomains.txt
│   └── directories.txt
│
└── .github/
    └── workflows/
        └── ci.yml            # Lint + import check on every push
```

---

## 🗺️ Roadmap

- [ ] Shodan API integration for passive port intelligence
- [ ] VirusTotal passive subdomain source
- [ ] Screenshots of discovered subdomains (via Playwright)
- [ ] Nuclei template integration for deeper vuln scanning
- [ ] Scan profiles (quick / full / stealth)
- [ ] Web UI dashboard
- [ ] Export to Markdown

---

## ⚠️ Disclaimer

This tool is intended **only for authorised security testing and educational purposes**. Always obtain explicit written permission before running any recon against a domain you do not own. The author is not responsible for any misuse.

---

## 🧰 Built With

[![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Click](https://img.shields.io/badge/Click-CLI-green?style=flat-square)](https://click.palletsprojects.com)
[![Rich](https://img.shields.io/badge/Rich-Terminal_UI-blueviolet?style=flat-square)](https://github.com/Textualize/rich)
[![aiohttp](https://img.shields.io/badge/aiohttp-Async_HTTP-blue?style=flat-square)](https://docs.aiohttp.org)
[![Jinja2](https://img.shields.io/badge/Jinja2-Templating-red?style=flat-square)](https://jinja.palletsprojects.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)

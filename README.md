# 🔍 Recon Toolkit

A modular command-line tool that automates web reconnaissance by discovering and analyzing a target's attack surface — built for bug bounty hunters and security researchers.

---

## 📸 Demo

> Run a full recon pipeline on any domain:
```bash
python cli.py full reddit.com
```

![Full Pipeline Output](assets/demo.png)

---

## ✨ Features

| Module | What it does |
|--------|-------------|
| **Subdomain Enumeration** | Discovers subdomains via wordlist + DNS resolution + HTTP probing |
| **Directory Discovery** | Brute-forces common paths and identifies accessible/restricted endpoints |
| **HTTP Analysis** | Detects missing security headers, cookie misconfigurations, and info leakage |
| **Vulnerability Checks** | Tests for open redirects, reflected input, CORS misconfig, and dangerous HTTP methods |

---

## 🚀 Installation
```bash
git clone https://github.com/liketosweep/recon-toolkit.git
cd recon-toolkit
pip install -r requirements.txt
```

---

## 🛠️ Usage

### Run individual modules:
```bash
python cli.py subdomains example.com
python cli.py directories example.com
python cli.py analyze example.com
python cli.py vulncheck example.com
```

### Run the full pipeline:
```bash
python cli.py full example.com
```

### Save results to a file:
```bash
python cli.py full example.com --output report.txt
```

### Custom wordlists:
```bash
python cli.py subdomains example.com --wordlist path/to/wordlist.txt
```

---

## 📁 Project Structure

recon-toolkit/
├── recon/
│   ├── subdomain.py       # Subdomain enumeration module
│   ├── directory.py       # Directory brute-forcing module
│   ├── http_analyzer.py   # HTTP header analysis module
│   └── vuln_checker.py    # Vulnerability checks module
├── wordlists/
│   ├── subdomains.txt     # Subdomain wordlist
│   └── directories.txt    # Directory wordlist
├── cli.py                 # Unified CLI entry point
└── requirements.txt

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Always get explicit permission before running recon on any domain you do not own. The author is not responsible for any misuse.

---

## 🧰 Built With

- [Python](https://python.org)
- [Click](https://click.palletsprojects.com) — CLI framework
- [Rich](https://github.com/Textualize/rich) — Terminal formatting
- [Requests](https://docs.python-requests.org) — HTTP requests
- [dnspython](https://www.dnspython.org) — DNS resolution
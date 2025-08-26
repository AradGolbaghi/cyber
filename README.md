
```
# 🔐 CYBER — Hacker-Life Lab

> A Python toolkit for recon, network scanning/sniffing, HTTP/OSINT helpers, PDF + image forensics, QR/EXIF tools, token analyzers, and more — with a colorful interactive TUI.  
> Cross-platform: **Linux, macOS, Windows**.

---

## 📂 Project Layout

```

CYBER/
├── .venv/             # optional virtual environment
├── .vscode/           # VS Code settings
├── HELPME.txt         # quick CLI examples
├── main.py            # main app (menu + CLI)
├── Makefile           # convenience commands
├── README.md          # this file
├── requirements.txt   # Python dependencies
└── setup.py           # cross-platform system+pip setup helper

```

---

## ✨ What it can do

**Networking & Recon**
- Async **Port Scanner + Banner** grabber, **HTTP Enumerator**, **robots.txt + sitemap**, **Traceroute** (Scapy), **ARP scan**, **CIDR /24 sweep**, **Bulk ping sweep**, **Public IP + Geo** lookup. :contentReference[oaicite:0]{index=0} :contentReference[oaicite:1]{index=1}

**Packets & PCAP**
- **Packet Sniffer** stats (SYN/DNS), **PCAP → IOC** (extract URLs/Hosts). :contentReference[oaicite:2]{index=2}

**HTTP / App security**
- **HTTP Fuzzer** (simple heuristic findings), **Security Headers audit**, **Dir brute-force**, **URL unshorten (redirect chain)**. :contentReference[oaicite:3]{index=3} :contentReference[oaicite:4]{index=4}

**Crypto & Misc**
- **JWT inspector**, **Codec box** (base64/url encode/decode), **Password generator**, **SSH key audit**, **Subnet calculator**, **Integrity baseline** (hash inventory + diff). :contentReference[oaicite:5]{index=5}

**PDF / Files**
- **PDF metadata reader** (pypdf → pdfminer fallback), **File Magic + strings** (libmagic & printable strings). :contentReference[oaicite:6]{index=6} :contentReference[oaicite:7]{index=7}

**Images / QR / EXIF**
- **Image Metadata Pro** (EXIF + GPS with decimal lat/lon), **EXIF scrub (rewrite clean copy)**, **Image duplicate finder (perceptual hash)**, **QR decode**. :contentReference[oaicite:8]{index=8} :contentReference[oaicite:9]{index=9} :contentReference[oaicite:10]{index=10}

**Tokens & Secrets**
- **Discord token analyzer + leak scan**, **Telegram bot token analyzer + deep-link builder**, **Secret scan (regex)** for common API keys. (All offline; redacts secrets.) :contentReference[oaicite:11]{index=11} :contentReference[oaicite:12]{index=12} :contentReference[oaicite:13]{index=13}

**Phone OSINT**
- Interactive and CLI **phone intelligence** (validity, E.164, carrier, region, TZ). :contentReference[oaicite:14]{index=14}

The interactive menu shows all tools and short descriptions. :contentReference[oaicite:15]{index=15}

---

## 🧰 Requirements

Python packages (installed via the Makefile or setup script):

```

pyfiglet, colorama, termcolor, rich, typer, requests, dnspython, scapy,
python-whois, phonenumbers, Pillow, qrcode\[pil], pyzbar, piexif, imagehash,
pypdf, pdfminer.six, zxcvbn, mmh3, python-magic, whois

````
(See `requirements.txt` for the authoritative list.) :contentReference[oaicite:16]{index=16}

Some features rely on system tools/libs (e.g., **tshark**, **tcpdump**, **ZBar**, **libmagic**). Use `setup.py` to install them where possible. :contentReference[oaicite:17]{index=17}

---

## ⚡ Quick Start

### 1) Create & activate a virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate       # Linux/macOS
# or on Windows PowerShell:
# .venv\Scripts\Activate.ps1
````

### 2) Install Python deps

```bash
make install
# or without venv:
make install-user
```

### 3) Run

```bash
make run                    # interactive menu
# or CLI:
python main.py --help
python main.py scan 127.0.0.1 --ports 1-1024 --timeout 0.5 --out scan.json
```

(These examples also live in `HELPME.txt`.)&#x20;

---

## 🛠 Optional: Cross-platform setup helper

`setup.py` can (best-effort) install **system packages** and **pip deps** on Linux/macOS/Windows. It also shows an ASCII banner and verifies imports.

**Flags:** `--no-open` (skip opening links), `--no-sys`, `--no-py`, `--no-verify`.
**Example:** `python setup.py --no-open` &#x20;

---

## 🧭 CLI Highlights

The app exposes a Typer CLI in addition to the menu:

* `menu` – launch interactive TUI
* `scan` – async port scanner with JSON output (`--ports`, `--timeout`, `--out`)
* `phone` – phone intelligence (region default, E.164, carrier, tz)&#x20;

---

## ⚠️ Legal / Ethics

Use these tools **only** on systems you own or have **explicit permission** to test. A first-run gate records your acknowledgment in `~/.hackerlife/config.json`.&#x20;

---

## 🤝 Contributing

1. Fork this repo
2. Create a feature branch (`git checkout -b feature/foo`)
3. Commit (`git commit -m "Add foo"`)
4. Push (`git push origin feature/foo`)
5. Open a Pull Request

---

## 📜 License

MIT — free to use, modify, and distribute.

```



# MADE BY ARAD GOL# cyber

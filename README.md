```
# ​ CYBER — Hacker-Life Lab

> A Python toolkit for recon, network scanning/sniffing, HTTP/OSINT helpers, PDF + image forensics, QR/EXIF tools, token analyzers, and more.  
> **Cross-platform**: Linux, macOS, Windows.

---

##  Project Layout

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

##  Features & Capabilities

**Networking & Recon**
- Port scanner with banner grabber, HTTP enumeration, robots.txt + sitemap fetcher, traceroute (Scapy), ARP scan, /24 CIDR sweep, bulk ping sweep, public IP + geolocation lookup.

**Packet Capture & PCAP**
- Packet sniffer stats (SYN/DNS) and PCAP parsing to extract IOCs (URLs/hosts).

**HTTP / Security Tools**
- HTTP fuzzer, security header audit, directory brute-forcer, URL unshorten (redirect chains).

**Crypto & Miscellaneous**
- JWT inspector, encoding/decoding toolbox (base64, URL), password generator, SSH key auditor, subnet calculator, integrity baseline (hashing + diff).

**PDF / File Analysis**
- PDF metadata reader (via `pypdf` or fallback to `pdfminer`), file magic detection, and printable string extraction.

**Images / QR / EXIF**
- EXIF metadata viewer with GPS-to-decimal conversion, EXIF scrubber, image duplicate detector (perceptual hash), and QR code decoder.

**Tokens & Secrets**
- Discord token analyzer with leak-scanning, Telegram bot token processor (deep link builder), and regex-based API key scanning—all offline and secrets masked.

**Phone Intelligence**
- Phone number OSINT (validity, E.164 conversion, carrier, region, timezone), accessible via both CLI and interactive menu.

---

##  Requirements

Install these Python dependencies via the Makefile or `setup.py`:

```

pyfiglet, colorama, termcolor, rich, typer, requests, dnspython, scapy,
python-whois, phonenumbers, Pillow, qrcode\[pil], pyzbar, piexif, imagehash,
pypdf, pdfminer.six, zxcvbn, mmh3, python-magic, whois

````

Some features require system libraries (e.g., `tshark`, `tcpdump`, ZBar, libmagic). Use `setup.py` to install them when possible.

---

##  Quick Start

1. **Create & activate virtual environment**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate       # Linux/macOS
   # or on Windows PowerShell:
   # .venv\Scripts\Activate.ps1
````

2. **Install dependencies**

   ```bash
   make install
   # or, skip venv:
   make install-user
   ```

3. **Run**

   ```bash
   make run               # launch interactive menu
   # Or via CLI:
   python main.py --help
   python main.py scan 127.0.0.1 --ports 1-1024 --timeout 0.5 --out scan.json
   ```

(See `HELPME.txt` for more examples.)

---

## Optional Setup Helper

Run `setup.py` to install Python packages and system tools (best-effort, cross-platform), show ASCII art, and verify imports.

**Flags:**

* `--no-open` – skip opening links
* `--no-sys` – skip system package installation
* `--no-py` – skip Python package installation
* `--no-verify` – skip import checks

Example:

```bash
python setup.py --no-open
```

---

## CLI Highlights (via Typer)

* `menu`: Launch the interactive TUI
* `scan`: Async port scanner

  ```bash
  python main.py scan <host> --ports <range> --timeout <sec> --out <file>
  ```
* `phone`: Phone number OSINT

  ```bash
  python main.py phone <number>
  ```

---

## Legal & Ethics

Use only on targets you have permission to test. First-run confirmation is stored in `~/.hackerlife/config.json`.

---

## Contributing

1. Fork the repo
2. Create a branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m "Add your feature"`)
4. Push (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## License

MIT — free to use, modify, and share.

```

---
## ✍️ Author
Made by **Arad Golbaghi**  

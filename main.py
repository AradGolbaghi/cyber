#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HACKER-LIFE LAB (Educational) — Extended Edition
A polished, modular, pretty-terminal toolkit of hacker-flavored (legal) utilities.

Run only on machines & targets you own or have explicit permission to test.
Tested on Python 3.10+ (Ubuntu). Some features may require sudo.

Recommended extras:
  pip install rich typer requests dnspython pillow scapy pyshark python-whois phonenumbers qrcode[pil]

Quick start:
  python3 main.py            # Interactive menu (Rich UI)
  python3 main.py --help     # CLI help (Typer)

Config:
  First run writes ~/.hackerlife/config.json with your preferences, including a
  one-time legality confirmation.
"""

from __future__ import annotations
import asyncio
import base64
import binascii
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse as urlparse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from queue import Queue
from hashlib import sha256

# ---------- Optional deps (graceful degradation) ----------
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress
    from rich import box
except Exception:  # fallback if rich isn't available
    Console = None
    Panel = None
    Table = None
    Text = None
    Prompt = None
    Confirm = None
    Progress = None
    box = None

# PDF libs (optional)
try:
    from pypdf import PdfReader as PYPDF_Reader
except Exception:
    PYPDF_Reader = None

try:
    # pdfminer.six fallback
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
except Exception:
    PDFParser = PDFDocument = None

try:
    import typer  # optional CLI
except Exception:
    typer = None

try:
    import requests
except Exception:
    requests = None

try:
    import dns.resolver  # dnspython
except Exception:
    dns = None

try:
    from PIL import Image, ExifTags
except Exception:
    Image = None
    ExifTags = None

# scapy bits
try:
    from scapy.all import sniff, rdpcap, TCP, DNS, DNSQR, arping
    try:
        from scapy.layers.inet import traceroute as scapy_traceroute
    except Exception:
        scapy_traceroute = None
except Exception:
    sniff = None
    rdpcap = None
    TCP = DNS = DNSQR = None
    arping = None
    scapy_traceroute = None

try:
    import whois  # python-whois
except Exception:
    whois = None

# New optional deps
try:
    import phonenumbers
    from phonenumbers import geocoder as phone_geocoder, carrier as phone_carrier, timezone as phone_timezone
except Exception:
    phonenumbers = None
    phone_geocoder = None
    phone_carrier = None
    phone_timezone = None

try:
    import qrcode
except Exception:
    qrcode = None

# ---------- Globals ----------
APP_NAME = "Hacker-Life Lab"
CFG_DIR = Path.home() / ".hackerlife"
CFG_FILE = CFG_DIR / "config.json"
REPORTS_DIR = CFG_DIR / "reports"
console = Console() if Console else None

# ---------- Utilities ----------

def cprint(*args, **kwargs):
    if console:
        console.print(*args, **kwargs)
    else:
        print(*args)


def ensure_config() -> dict:
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if CFG_FILE.exists():
        try:
            return json.loads(CFG_FILE.read_text())
        except Exception:
            pass
    cfg = {
        "agreed_legal": False,
        "defaults": {
            "sniffer_iface": None,
            "http_fuzz_wordlist": None,
        },
    }
    CFG_FILE.write_text(json.dumps(cfg, indent=2))
    return cfg


def save_json_report(name: str, payload: dict | list) -> Path:
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    path = REPORTS_DIR / f"{name}-{ts}.json"
    path.write_text(json.dumps(payload, indent=2, default=str))
    return path


# ---------- Pretty Shell ----------
ASCII = r"""
 _   _            _               _     _  __ _      _        _      _     
| | | | __ _  ___| | _____ _ __  | |   (_)/ _(_) ___| | _____| |__  | |__  
| |_| |/ _` |/ __| |/ / _ \ '__| | |   | | |_| |/ __| |/ / _ \ '_ \ | '_ \ 
|  _  | (_| | (__|   <  __/ |    | |___| |  _| | (__|   <  __/ | | || | | |
|_| |_|\__,_|\___|_|\_\___|_|    |_____|_|_| |_|\___|_|\_\___|_| |_||_| |_|
"""


@dataclass
class Tool:
    key: str
    name: str
    desc: str
    fn: Callable[[], None]


# ---------- Core Tools ----------
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
    5900: "vnc", 6379: "redis", 8080: "http-alt",
}

PROBES = {
    "http": b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    "https": b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    "ssh": b"",
    "smtp": b"EHLO localhost\r\n",
    "imap": b". CAPABILITY\r\n",
    "pop3": b"QUIT\r\n",
    "redis": b"PING\r\n",
    "mysql": b"",
}


async def _check_port(host: str, port: int, timeout: float = 1.0):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return None
    service = COMMON_PORTS.get(port, "unknown")
    banner = b""
    try:
        probe = PROBES.get(service, b"")
        if probe:
            writer.write(probe)
            await writer.drain()
        banner = await asyncio.wait_for(reader.read(256), timeout=0.8)
    except Exception:
        pass
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    text = banner.decode(errors="ignore").strip()
    return {"port": port, "service_guess": service, "banner": text[:500]}


async def _scan_host(host: str, ports: List[int], concurrency: int = 500, timeout: float = 1.0):
    sem = asyncio.Semaphore(concurrency)

    async def sem_task(p):
        async with sem:
            return await _check_port(host, p, timeout=timeout)

    tasks = [asyncio.create_task(sem_task(p)) for p in ports]
    results = []
    for coro in asyncio.as_completed(tasks):
        res = await coro
        if res:
            results.append(res)
    return sorted(results, key=lambda r: r["port"])

def _safe_import_pillow():
    """Return (Image, ExifTags) or (None, None) without crashing if Pillow is missing."""
    try:
        from PIL import Image as _Image, ExifTags as _ExifTags  # type: ignore
        return _Image, _ExifTags
    except Exception:
        return None, None

def tool_port_scanner():
    target = Prompt.ask("[bold]Target[/] (hostname/IP)") if console else input("Target: ")
    mode = Prompt.ask("[bold]Ports[/] ('top1k' or e.g. 1-1024,80,443)", default="top1k") if console else input("Ports: ")
    timeout = float(Prompt.ask("Timeout per port (s)", default="1.0")) if console else float(input("Timeout: ") or 1.0)
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        cprint(f"[red]DNS failed:[/] {e}")
        return
    if mode.strip().lower() == "top1k":
        ports = sorted(set(list(COMMON_PORTS.keys()) + list(range(1, 1025))))
    else:
        ports = []
        for seg in mode.split(","):
            seg = seg.strip()
            if not seg:
                continue
            if "-" in seg:
                a, b = seg.split("-", 1)
                ports += list(range(int(a), int(b) + 1))
            else:
                ports.append(int(seg))
        ports = sorted(set(ports))

    cprint(f"[cyan]Scanning[/] {target} ({ip}) on {len(ports)} ports …")
    with (Progress() if console else nullcontext()):
        results = asyncio.run(_scan_host(ip, ports, timeout=timeout))
    table = Table(title=f"Open Ports for {target} ({ip})", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Port", justify="right")
    table.add_column("Service")
    table.add_column("Banner/Hint", overflow="fold")
    for r in results:
        table.add_row(str(r["port"]), r["service_guess"], r["banner"] or "")
    cprint(table)
    if Confirm.ask("Save JSON report?", default=True):
        p = save_json_report("port-scan", {"target": target, "ip": ip, "open_ports": results})
        cprint(f"[green]Saved[/] {p}")


def tool_sniffer():
    if sniff is None:
        cprint("[yellow]scapy required:[/] pip install scapy (and run with sudo)")
        return
    cfg = ensure_config()
    iface_default = cfg["defaults"].get("sniffer_iface")
    iface = Prompt.ask("Interface (e.g. eth0, wlan0)", default=str(iface_default or "")) if console else input("Interface: ")
    count = int(Prompt.ask("Packets to capture", default="80")) if console else int(input("Count: ") or 80)
    cprint("Capturing … (Ctrl+C to stop)")
    pkts = sniff(iface=iface or None, count=count, timeout=30)
    syns = 0
    dnsq = 0
    for p in pkts:
        try:
            if TCP in p and getattr(p[TCP], 'flags', None) == 'S':
                syns += 1
            if DNS in p and getattr(p[DNS], 'qd', None) and isinstance(p[DNS].qd, DNSQR):
                dnsq += 1
        except Exception:
            pass
    cprint(f"Captured: [bold]{len(pkts)}[/] | TCP SYNs: [bold]{syns}[/] | DNS queries: [bold]{dnsq}[/]")


def tool_http_fuzzer():
    if requests is None:
        cprint("[yellow]requests required:[/] pip install requests")
        return
    url = Prompt.ask("Target URL (use TEST placeholder)", default="http://127.0.0.1:3000/?q=TEST") if console else input("URL: ")
    wl = Prompt.ask("Wordlist file (blank for builtin)", default="") if console else input("Wordlist: ")
    payloads = ["<script>alert(1)</script>", "' OR '1'='1", "../../etc/passwd", "%3Cscript%3Ealert(1)%3C/script%3E"]
    if wl and os.path.isfile(wl):
        payloads = [x.strip() for x in Path(wl).read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
    cprint(f"Fuzzing [bold]{url}[/] with {len(payloads)} payloads …")
    hits = []
    for p in payloads:
        try:
            r = requests.get(url.replace("TEST", p), timeout=5)
            indicators = []
            lt = r.text.lower()
            if "alert(1)" in lt:
                indicators.append("reflected-xss?")
            if "syntax" in lt or "sql" in lt:
                indicators.append("sqli-noise?")
            if r.status_code >= 500:
                indicators.append("500-error")
            if indicators:
                hits.append({"payload": p, "indicators": indicators, "status": r.status_code})
        except Exception:
            pass
    table = Table(title="Potential Findings", box=box.SIMPLE)
    table.add_column("Payload")
    table.add_column("Indicators")
    table.add_column("Status")
    for h in hits:
        table.add_row(h["payload"], ", ".join(h["indicators"]), str(h["status"]))
    if not hits:
        cprint("[green]No obvious issues detected by simple heuristics.[/]")


def tool_mini_siem():
    path_default = "/var/log/auth.log"
    path = Prompt.ask("Auth log path", default=path_default) if console else input("Auth log: ") or path_default
    if not os.path.exists(path):
        cprint("[red]Log not found or insufficient permissions.[/]")
        return
    cprint("Watching for brute-force patterns … (Ctrl+C to stop)")
    stop_evt = threading.Event()
    ql: Queue[str] = Queue()

    def tail_file():
        with open(path, "r", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            while not stop_evt.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                ql.put(line)

    t = threading.Thread(target=tail_file, daemon=True)
    t.start()
    failed_re = re.compile(r"Failed password for (invalid user )?(\S+) from ([0-9.]+) port")
    success_re = re.compile(r"Accepted \S+ for (\S+) from ([0-9.]+) port")
    failures: Dict[tuple, int] = {}
    try:
        while True:
            line = ql.get()
            m = failed_re.search(line)
            if m:
                user, ip = m.group(2), m.group(3)
                key = (user, ip)
                failures[key] = failures.get(key, 0) + 1
                if failures[key] in (5, 10, 20):
                    cprint(f"[bold red]ALERT[/] Repeated failed logins user={user} ip={ip} count={failures[key]}")
                continue
            m = success_re.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                cprint(f"[green]INFO[/] Successful login user={user} ip={ip}")
    except KeyboardInterrupt:
        stop_evt.set()
        cprint("Stopped.")


def _serve_tcp(port: int, stop_evt: threading.Event):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    cprint(f"[cyan]Honeypot listening[/] on {port}")
    s.settimeout(1.0)
    try:
        while not stop_evt.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            cprint(f"[+] Connection from {addr[0]}:{addr[1]} on {port}")
            try:
                conn.sendall(b"Welcome\r\n")
                data = conn.recv(512)
                if data:
                    preview = data[:200].replace(b"\r", b" ").replace(b"\n", b" ")
                    cprint(f"    Data: {preview!r}")
                conn.close()
            except Exception:
                pass
    finally:
        s.close()


def tool_honeypot():
    ports_s = Prompt.ask("Ports (comma, high ports e.g. 2222,8080)", default="2222,8080") if console else input("Ports: ") or "2222,8080"
    try:
        port_list = sorted({int(p.strip()) for p in ports_s.split(",") if p.strip()})
    except Exception:
        cprint("[red]Invalid port list[/]")
        return
    stop_evt = threading.Event()
    threads = []
    for p in port_list:
        t = threading.Thread(target=_serve_tcp, args=(p, stop_evt), daemon=True)
        t.start()
        threads.append(t)
    cprint("Press Ctrl+C to stop …")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_evt.set()
        cprint("Stopping honeypot …")


def tool_tls_auditor():
    host = Prompt.ask("Hostname", default="example.com") if console else input("Hostname: ")
    try:
        port = int(Prompt.ask("Port", default="443")) if console else int(input("Port: ") or 443)
    except Exception:
        port = 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                ciphers = ssock.shared_ciphers()
                version = ssock.version()
    except Exception as e:
        cprint(f"[red]TLS fetch failed:[/] {e}")
        return
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    table = Table(title=f"TLS Report for {host}:{port}", box=box.MINIMAL)
    table.add_column("Field")
    table.add_column("Value", overflow="fold")
    rows = [
        ("TLS Version", version or ""),
        ("Subject CN", subject.get("commonName", "")),
        ("Issuer CN", issuer.get("commonName", "")),
        ("Valid From", cert.get("notBefore", "")),
        ("Valid To", cert.get("notAfter", "")),
        ("SANs", ", ".join(v for k, v in cert.get("subjectAltName", []) if k == "DNS")),
        ("Shared Ciphers", str(len(ciphers or []))),
    ]
    for k, v in rows:
        table.add_row(k, v)
    cprint(table)


def tool_forensics():
    path = Prompt.ask("Path to file or directory", default=str(Path.cwd())) if console else input("Path: ") or str(Path.cwd())
    p = Path(path)
    if not p.exists():
        cprint("[red]Path not found[/]")
        return
    files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
    table = Table(title=f"Forensics: {path}", box=box.SIMPLE)
    table.add_column("File")
    table.add_column("Size")
    table.add_column("SHA256 (prefix)")
    for f in files[:1000]:  # safety cap
        try:
            h = sha256()
            with open(f, 'rb') as fh:
                for chunk in iter(lambda: fh.read(65536), b''):
                    h.update(chunk)
            hs = h.hexdigest()
            table.add_row(str(f), str(f.stat().st_size), hs[:16])
        except Exception:
            pass
    cprint(table)
    if Image and any(f.suffix.lower() in {'.jpg','.jpeg','.png','.tiff'} for f in files):
        if Confirm.ask("Extract EXIF from images?", default=False):
            for f in files:
                if f.suffix.lower() not in {'.jpg','.jpeg','.png','.tiff'}:
                    continue
                try:
                    img = Image.open(f)
                    info = img._getexif() or {}
                    if not info:
                        continue
                    inv = {ExifTags.TAGS.get(k, k): v for k, v in info.items()}
                    cprint(Panel.fit(json.dumps(inv, indent=2, default=str), title=str(f), box=box.ROUNDED))
                except Exception:
                    pass


def tool_wordlist_rules():
    base = Prompt.ask("Base words (comma)", default="admin,football") if console else input("Base words: ")
    words = [w.strip() for w in base.split(',') if w.strip()]
    LEET_MAP = str.maketrans({"a":"4","e":"3","i":"1","o":"0","s":"5","t":"7"})
    SUFFIXES = ["!","123","2024","2025","@","#","_","01"]
    outs = set()
    for w in words:
        outs.update({w, w.lower(), w.upper(), w.capitalize(), w[::-1], w.translate(LEET_MAP)})
        for s in SUFFIXES:
            outs.add(w + s)
            outs.add(w.capitalize() + s)
    outs = sorted(outs)
    cprint(f"Generated [bold]{len(outs)}[/] candidates. Showing first 60:")
    for i, v in enumerate(outs[:60], 1):
        cprint(f"{i:>3}. {v}")
    if Confirm.ask("Save to wordlist file?", default=False):
        out = Prompt.ask("Filename", default=str(REPORTS_DIR / "wordlist.txt"))
        Path(out).write_text("\n".join(outs))
        cprint(f"[green]Saved[/] {out}")


def resolve_dns(name: str) -> List[str]:
    if dns and hasattr(dns, "resolver"):
        try:
            answers = dns.resolver.resolve(name, "A")
            return [a.address for a in answers]
        except Exception:
            return []
    try:
        _, _, addrs = socket.gethostbyname_ex(name)
        return addrs or []
    except Exception:
        return []


def tool_dns_intel():
    domain = Prompt.ask("Root domain", default="example.com") if console else input("Domain: ")
    wordlist = Prompt.ask("Subdomain wordlist (blank builtin)", default="") if console else input("Wordlist: ")
    subs = ["www","api","admin","dev","staging","test","mail"]
    if wordlist and os.path.isfile(wordlist):
        subs = [x.strip() for x in Path(wordlist).read_text(encoding='utf-8', errors='ignore').splitlines() if x.strip()]
    results = []
    for s in subs:
        fqdn = f"{s}.{domain}"
        addrs = resolve_dns(fqdn)
        if addrs:
            results.append((fqdn, ", ".join(addrs)))
    table = Table(title=f"DNS Intel: {domain}", box=box.SIMPLE)
    table.add_column("Host")
    table.add_column("IP(s)")
    for h, a in results:
        table.add_row(h, a)
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("dns-intel", [{"host": h, "ips": a.split(', ')} for h, a in results])
        cprint(f"[green]Saved[/] {p}")


def tool_pcap_ioc():
    if rdpcap is None:
        cprint("[yellow]scapy required:[/] pip install scapy")
        return
    pcap = Prompt.ask("PCAP file path", default="capture.pcap") if console else input("PCAP: ")
    if not os.path.exists(pcap):
        cprint("[red]File not found[/]")
        return
    pkts = rdpcap(pcap)
    URL_RE = re.compile(rb"https?://[a-zA-Z0-9\.\-_/~%?=&+#:]+")
    HOST_RE = re.compile(rb"Host:\s*([^\r\n]+)", re.IGNORECASE)
    urls, hosts = set(), set()
    for p in pkts:
        try:
            raw = bytes(p)
        except Exception:
            continue
        for m in URL_RE.finditer(raw):
            urls.add(m.group(0).decode("utf-8", errors="ignore"))
        for m in HOST_RE.finditer(raw):
            hosts.add(m.group(1).decode("utf-8", errors="ignore").strip())
    table = Table(title="PCAP → IOC", box=box.SIMPLE)
    table.add_column("Type")
    table.add_column("Value", overflow="fold")
    for u in sorted(list(urls))[:20]:
        table.add_row("URL", u)
    for h in sorted(list(hosts))[:20]:
        table.add_row("Host", h)
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("pcap-ioc", {
            "ioc_type": "network",
            "extracted_utc": datetime.utcnow().isoformat()+"Z",
            "urls": sorted(urls),
            "hosts": sorted(hosts),
        })
        cprint(f"[green]Saved[/] {p}")


# ---------- New bonus tools (existing 21–30 retained below we’ll add more later) ----------

def tool_cidr_sweep():
    """Quick host sweep across a /24 or custom list, with port 80/443 ping.
    Only runs on RFC1918 ranges for safety.
    """
    net = Prompt.ask("CIDR (private only, e.g. 192.168.1.0/24)", default="192.168.1.0/24") if console else input("CIDR: ")
    try:
        network = ipaddress.ip_network(net, strict=False)
        if not (network.is_private and (network.prefixlen <= 24)):
            cprint("[red]Refusing non-private or too large network.[/]")
            return
    except Exception:
        cprint("[red]Invalid CIDR[/]")
        return
    hosts = [str(h) for h in network.hosts()]
    targets = hosts[:256]

    async def check(host: str):
        open_hint = []
        for port in (80, 443):
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=0.3)
                open_hint.append(port)
                w.close(); await w.wait_closed()
            except Exception:
                pass
        return host if open_hint else None

    async def run_all():
        tasks = [asyncio.create_task(check(h)) for h in targets]
        found = []
        for c in asyncio.as_completed(tasks):
            res = await c
            if res:
                found.append(res)
        return found

    cprint(f"Sweeping {len(targets)} hosts …")
    found = asyncio.run(run_all())
    table = Table(title="CIDR sweep results", box=box.SIMPLE)
    table.add_column("Host")
    for h in found:
        table.add_row(h)
    cprint(table)


def tool_whois():
    if whois is None:
        cprint("[yellow]python-whois required:[/] pip install python-whois")
        return
    domain = Prompt.ask("Domain for WHOIS", default="example.com") if console else input("Domain: ")
    try:
        w = whois.whois(domain)
        data = {k: v for k, v in w.__dict__.items() if not k.startswith('_')}
        cprint(Panel.fit(json.dumps(data, indent=2, default=str), title=f"WHOIS: {domain}"))
    except Exception as e:
        cprint(f"[red]WHOIS failed:[/] {e}")


def tool_http_enum():
    """Fetch one or more URLs, show status, title, server header, tech hints."""
    if requests is None:
        cprint("[yellow]requests required:[/] pip install requests")
        return
    urls = Prompt.ask("URLs (comma)", default="http://localhost,http://127.0.0.1:8000") if console else input("URLs: ")
    targets = [u.strip() for u in urls.split(',') if u.strip()]
    table = Table(title="HTTP Enumerator", box=box.MINIMAL)
    table.add_column("URL")
    table.add_column("Status")
    table.add_column("Server")
    table.add_column("Title", overflow="fold")
    for u in targets:
        try:
            r = requests.get(u, timeout=5, allow_redirects=True)
            server = r.headers.get('Server', '')
            m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE|re.DOTALL)
            title = (m.group(1).strip() if m else '')
            table.add_row(u, str(r.status_code), server, title)
        except Exception as e:
            table.add_row(u, "ERR", "", str(e))
    cprint(table)


def b64url_decode(s: str) -> bytes:
    s = s.strip().replace('-', '+').replace('_', '/')
    pad = len(s) % 4
    if pad:
        s += '=' * (4 - pad)
    return base64.b64decode(s)


def tool_jwt_inspector():
    token = Prompt.ask("JWT (paste)") if console else input("JWT: ")
    parts = token.split('.')
    if len(parts) != 3:
        cprint("[red]Not a JWT (expected 3 parts)[/]")
        return
    try:
        header = json.loads(b64url_decode(parts[0]).decode('utf-8','ignore'))
        payload = json.loads(b64url_decode(parts[1]).decode('utf-8','ignore'))
        sig_b64 = parts[2]
    except Exception as e:
        cprint(f"[red]Decode error:[/] {e}")
        return
    table = Table(title="JWT Inspector", box=box.SIMPLE)
    table.add_column("Section")
    table.add_column("JSON", overflow="fold")
    table.add_row("Header", json.dumps(header, indent=2))
    table.add_row("Payload", json.dumps(payload, indent=2))
    table.add_row("Signature", sig_b64)
    cprint(table)
    if requests and Confirm.ask("Fetch JWKs from issuer (if iss claim present)?", default=False):
        iss = payload.get('iss')
        if not iss:
            cprint("[yellow]No 'iss' claim present.[/]")
        else:
            jwk_url = urlparse.urljoin(iss if iss.endswith('/') else iss+'/', '.well-known/jwks.json')
            try:
                r = requests.get(jwk_url, timeout=6)
                cprint(Panel.fit(r.text[:4000], title=f"JWKs from {jwk_url}"))
            except Exception as e:
                cprint(f"[red]JWK fetch failed:[/] {e}")


def tool_codec_box():
    """Encode/Decode helper: base64/base64url/url encode/decode"""
    mode = Prompt.ask("Mode", choices=["b64enc","b64dec","b64urlenc","b64urldec","urlenc","urldec"], default="b64enc") if console else input("Mode: ")
    data = Prompt.ask("Input text") if console else input("Input: ")
    try:
        if mode == "b64enc":
            out = base64.b64encode(data.encode()).decode()
        elif mode == "b64dec":
            out = base64.b64decode(data).decode('utf-8','ignore')
        elif mode == "b64urlenc":
            out = base64.urlsafe_b64encode(data.encode()).decode().rstrip('=')
        elif mode == "b64urldec":
            out = b64url_decode(data).decode('utf-8','ignore')
        elif mode == "urlenc":
            out = urlparse.quote_plus(data)
        else:
            out = urlparse.unquote_plus(data)
        cprint(Panel.fit(out, title="Result", box=box.ROUNDED))
    except binascii.Error as e:
        cprint(f"[red]Codec error:[/] {e}")


def tool_pwdgen():
    import secrets, string
    length = int(Prompt.ask("Length", default="20")) if console else int(input("Length: ") or 20)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    pw = ''.join(secrets.choice(alphabet) for _ in range(length))
    entropy = math.log2(len(alphabet)) * length
    cprint(Panel.fit(f"{pw}\n\nEstimated entropy: {entropy:.1f} bits", title="Password Generator"))


def tool_ssh_audit():
    """Audit ~/.ssh/*.pub key sizes and types."""
    ssh_dir = Path.home()/'.ssh'
    if not ssh_dir.exists():
        cprint("[yellow]~/.ssh not found[/]")
        return
    table = Table(title="SSH Public Keys", box=box.MINIMAL)
    table.add_column("File")
    table.add_column("Type")
    table.add_column("Bits")
    for pub in ssh_dir.glob('*.pub'):
        try:
            text = pub.read_text().strip()
            parts = text.split()
            ktype = parts[0]
            key_b64 = parts[1]
            raw = base64.b64decode(key_b64 + '===')
            bits = None
            if ktype.startswith('ssh-rsa') and len(raw) > 270:
                bits = 2048 if len(raw) < 400 else 4096
            elif ktype.startswith('ssh-ed25519'):
                bits = 256
            table.add_row(pub.name, ktype, str(bits or '?'))
        except Exception:
            table.add_row(pub.name, 'parse-error', '?')
    cprint(table)


def tool_http_robots():
    if requests is None:
        cprint("[yellow]requests required:[/] pip install requests")
        return
    base = Prompt.ask("Site (scheme+host)", default="https://example.com") if console else input("Site: ")
    u = base.rstrip('/') + '/robots.txt'
    sm = base.rstrip('/') + '/sitemap.xml'
    try:
        r = requests.get(u, timeout=6)
        cprint(Panel.fit(r.text[:4000] or "<empty>", title=f"robots.txt @ {u}"))
    except Exception as e:
        cprint(f"[red]robots fetch failed:[/] {e}")
    try:
        r2 = requests.get(sm, timeout=6)
        if r2.status_code == 200:
            cprint(Panel.fit(r2.text[:4000], title=f"sitemap.xml @ {sm}"))
    except Exception:
        pass


def tool_subnet_calc():
    cidr = Prompt.ask("CIDR", default="192.168.1.0/24") if console else input("CIDR: ")
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        cprint("[red]Invalid CIDR[/]")
        return
    table = Table(title="Subnet Calculator", box=box.SIMPLE)
    table.add_column("Field")
    table.add_column("Value")
    hosts_count = net.num_addresses - (2 if net.version==4 and net.prefixlen<31 else 0)
    first_host = str(list(net.hosts())[0]) if net.num_addresses>2 else str(net.network_address)
    last_host  = str(list(net.hosts())[-1]) if net.num_addresses>2 else str(net.broadcast_address)
    rows = [
        ("Network", str(net.network_address)),
        ("Broadcast", str(net.broadcast_address)),
        ("Netmask", str(net.netmask)),
        ("Hosts", str(hosts_count)),
        ("First Usable", first_host),
        ("Last Usable", last_host),
    ]
    for k,v in rows:
        table.add_row(k, v)
    cprint(table)


def dir_hash_inventory(path: Path) -> List[dict]:
    files = [path] if path.is_file() else [f for f in path.rglob('*') if f.is_file()]
    out = []
    for f in files:
        try:
            h = sha256()
            with open(f,'rb') as fh:
                for chunk in iter(lambda: fh.read(65536), b''):
                    h.update(chunk)
            out.append({"path": str(f), "size": f.stat().st_size, "sha256": h.hexdigest()})
        except Exception:
            pass
    return out


def tool_integrity_baseline():
    """Create or compare a hash baseline for a directory."""
    action = Prompt.ask("Action", choices=["create","compare"], default="create") if console else input("Action: ")
    target = Path(Prompt.ask("Target path", default=str(Path.cwd()))) if console else Path(input("Path: ") or str(Path.cwd()))
    if action == "create":
        inv = dir_hash_inventory(target)
        p = save_json_report("integrity-baseline", inv)
        cprint(f"[green]Baseline saved[/] {p}")
        return
    # compare
    base = Prompt.ask("Baseline JSON path") if console else input("Baseline JSON: ")
    try:
        baseline = json.loads(Path(base).read_text())
    except Exception as e:
        cprint(f"[red]Failed to read baseline:[/] {e}")
        return
    now = {i['path']: i for i in dir_hash_inventory(target)}
    before = {i['path']: i for i in baseline}
    added = [p for p in now.keys() - before.keys()]
    removed = [p for p in before.keys() - now.keys()]
    changed = [p for p in now.keys() & before.keys() if now[p]['sha256'] != before[p]['sha256']]
    table = Table(title="Integrity Diff", box=box.SIMPLE)
    table.add_column("Change")
    table.add_column("Path", overflow="fold")
    for p in added:
        table.add_row("+ added", p)
    for p in removed:
        table.add_row("- removed", p)
    for p in changed:
        table.add_row("~ changed", p)
    cprint(table)


# ---------- Menu & Routing ----------
TOOLS: List[Tool] = [
    Tool("1", "Port Scanner + Banner", "Async scan & lightweight banner grabs", tool_port_scanner),
    Tool("2", "Packet Sniffer", "Capture quick stats (SYNs, DNS queries)", tool_sniffer),
    Tool("3", "HTTP Fuzzer (local)", "Fuzz TEST placeholder with simple heuristics", tool_http_fuzzer),
    Tool("4", "Mini SIEM (auth.log)", "Tail SSH failures/success and alert on bursts", tool_mini_siem),
    Tool("5", "Honeypot-Lite", "Simple TCP listeners logging connections", tool_honeypot),
    Tool("6", "TLS/Cert Auditor", "Show CN, issuer, dates, TLS version", tool_tls_auditor),
    Tool("7", "Forensics (hash+EXIF)", "SHA256 inventory and optional EXIF dump", tool_forensics),
    Tool("8", "Wordlist Rule Engine", "Leetspeak + suffix transforms", tool_wordlist_rules),
    Tool("9", "DNS Intelligence", "Subdomain resolve table", tool_dns_intel),
    Tool("10", "PCAP → IOC Miner", "Extract URLs/Hosts from pcap", tool_pcap_ioc),
    Tool("11", "CIDR Web Sweep (private)", "Quick 80/443 sweep on /24 private", tool_cidr_sweep),
    Tool("12", "WHOIS Lookup", "Basic domain WHOIS (python-whois)", tool_whois),
    Tool("13", "HTTP Enumerator", "Fetch headers, status, <title> for URLs", tool_http_enum),
    Tool("14", "JWT Inspector", "Decode header/payload; optional JWK fetch", tool_jwt_inspector),
    Tool("15", "Codec Box", "Base64/base64url/URL encode/decode", tool_codec_box),
    Tool("16", "Password Generator", "Strong random password + entropy", tool_pwdgen),
    Tool("17", "SSH Key Audit", "Check ~/.ssh/*.pub types & sizes", tool_ssh_audit),
    Tool("18", "robots.txt + sitemap", "Quick fetch for discovery", tool_http_robots),
    Tool("19", "Subnet Calculator", "Show netmask, hosts, ranges", tool_subnet_calc),
    Tool("20", "Integrity Baseline", "Create/compare hash baseline of dir", tool_integrity_baseline),
]

class nullcontext:
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False


def first_run_legal_gate(cfg: dict) -> bool:
    if cfg.get("agreed_legal"):
        return True
    if console:
        cprint(Panel.fit("""
[bold]Legal Reminder[/]
Use these tools only on assets you own or are explicitly authorized to test.
Some features may require elevated privileges. Proceed?
""".strip(), title="Stay Ethical", border_style="yellow"))
        if not Confirm.ask("I understand and agree", default=False):
            cprint("Okay. Exiting.")
            return False
    cfg["agreed_legal"] = True
    (CFG_DIR/"README.txt").write_text("Hacker-Life Lab config directory. Reports saved in ./reports\n")
    CFG_FILE.write_text(json.dumps(cfg, indent=2))
    return True


def interactive_menu():
    cfg = ensure_config()
    if not first_run_legal_gate(cfg):
        return
    while True:
        if console:
            header = Panel.fit(Text(ASCII, justify="center"), title=APP_NAME, border_style="cyan")
            cprint(header)
            tbl = Table(box=box.MINIMAL_DOUBLE_HEAD)
            tbl.add_column("#", justify="right", style="bold")
            tbl.add_column("Tool")
            tbl.add_column("What it does")
            for t in TOOLS:
                tbl.add_row(t.key, t.name, t.desc)
            cprint(tbl)
            cprint("[dim]Type number to run. 'q' quit. 'cfg' config. Use /text to filter (e.g. /http).[/]")
            raw = Prompt.ask("Select", default="1")
            if raw.startswith("/"):
                q = raw[1:].lower().strip()
                ftbl = Table(box=box.MINIMAL_DOUBLE_HEAD)
                ftbl.add_column("#", justify="right", style="bold")
                ftbl.add_column("Tool")
                ftbl.add_column("What it does")
                for t in TOOLS:
                    if q in t.name.lower() or q in t.desc.lower():
                        ftbl.add_row(t.key, t.name, t.desc)
                cprint(ftbl)
                continue
            choice = raw
        else:
            print(ASCII)
            for t in TOOLS:
                print(f"{t.key}) {t.name} — {t.desc}")
            choice = input("Select (q to quit): ").strip()
        if choice.lower() in {"q", "quit", "exit"}:
            break
        if choice.lower() in {"cfg", "config"}:
            cprint(Panel.fit(str(CFG_DIR), title="Config directory"))
            continue
        tool = next((t for t in TOOLS if t.key == choice.strip()), None)
        if not tool:
            cprint("[red]Invalid choice[/]")
            continue
        try:
            tool.fn()
        except KeyboardInterrupt:
            cprint("\n[yellow]Interrupted[/]")
        except Exception as e:
            cprint(f"[red]Error:[/] {e}")
        if console:
            Confirm.ask("Back to menu?", default=True)


# ---------- NEW TOOLS (21–25) ----------

def tool_http_sec_headers():
    """Audit common HTTP security headers and HTTPS best practices."""
    if requests is None:
        cprint("[yellow]requests required:[/] pip install requests")
        return
    url = Prompt.ask("URL", default="https://example.com") if console else input("URL: ")
    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
    except Exception as e:
        cprint(f"[red]Request failed:[/] {e}")
        return
    needed = [
        ("Content-Security-Policy", "Helps prevent XSS by whitelisting sources"),
        ("X-Frame-Options", "Mitigates clickjacking (use 'DENY' or 'SAMEORIGIN')"),
        ("X-Content-Type-Options", "Stop MIME sniffing (use 'nosniff')"),
        ("Referrer-Policy", "Limit referer info leaking"),
        ("Permissions-Policy", "Limit powerful browser features (camera, mic)"),
        ("Strict-Transport-Security", "Force HTTPS (preload, includeSubDomains)"),
    ]
    table = Table(title=f"HTTP Security Headers @ {url}", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Header")
    table.add_column("Present")
    table.add_column("Value", overflow="fold")
    table.add_column("Why it matters", overflow="fold")
    hdrs = r.headers
    for h, why in needed:
        val = hdrs.get(h)
        ok = "✅" if val else "❌"
        table.add_row(h, ok, val or "<missing>", why)
    cprint(table)
    cprint(f"Status: [bold]{r.status_code}[/]  Server: [dim]{hdrs.get('Server','')}</dim]")


def tool_traceroute():
    """Network path discovery using scapy (best) or simple fallback."""
    dest = Prompt.ask("Destination host/IP", default="8.8.8.8") if console else input("Dest: ")
    if scapy_traceroute:
        try:
            res, _ = scapy_traceroute(dest, maxttl=20, verbose=0)
            table = Table(title=f"Traceroute to {dest}", box=box.SIMPLE)
            table.add_column("Hop", justify="right")
            table.add_column("IP")
            table.add_column("RTT (ms)")
            for snd, rcv in res:
                try:
                    hop = rcv.ttl  # may be missing
                except Exception:
                    hop = "?"
                ip = rcv.src
                rtt = int((rcv.time - snd.sent_time)*1000)
                table.add_row(str(hop), ip, str(rtt))
            cprint(table)
            return
        except Exception as e:
            cprint(f"[yellow]scapy traceroute failed:[/] {e}.")
    cprint("[red]Traceroute fallback not available without scapy/raw sockets.[/]")


def tool_arp_scan():
    """ARP scan a local subnet for live hosts (scapy arping)."""
    if arping is None:
        cprint("[yellow]scapy required:[/] pip install scapy (and run with sudo)")
        return
    cidr = Prompt.ask("CIDR (local, e.g. 192.168.1.0/24)", default="192.168.1.0/24") if console else input("CIDR: ")
    try:
        ans, _ = arping(cidr, verbose=0)
    except PermissionError:
        cprint("[red]Permission denied. Run with sudo for ARP scan.[/]")
        return
    table = Table(title=f"ARP Scan {cidr}", box=box.MINIMAL)
    table.add_column("IP")
    table.add_column("MAC")
    for _, rcv in ans:
        table.add_row(rcv.psrc, rcv.src)
    cprint(table)


def tool_http_dir_enum():
    """Simple directory brute-forcer (for local labs)."""
    if requests is None:
        cprint("[yellow]requests required:[/] pip install requests")
        return
    base = Prompt.ask("Base URL", default="http://127.0.0.1:8000/") if console else input("Base URL: ")
    wl = Prompt.ask("Wordlist file (blank small builtin)", default="") if console else input("Wordlist: ")
    paths = ["admin","login","uploads",".git/","backup","api","test","dev","config","dashboard"]
    if wl and os.path.isfile(wl):
        paths = [x.strip().lstrip('/') for x in Path(wl).read_text(encoding='utf-8', errors='ignore').splitlines() if x.strip()]
    base = base.rstrip('/') + '/'
    table = Table(title=f"Dir Enum @ {base}", box=box.SIMPLE)
    table.add_column("Path")
    table.add_column("Status")
    table.add_column("Len")
    for p in paths:
        url = base + p
        try:
            r = requests.get(url, timeout=4, allow_redirects=False)
            if r.status_code in (200, 204, 301, 302, 401, 403):
                table.add_row('/'+p, str(r.status_code), str(len(r.content)))
        except Exception:
            pass
    cprint(table)


HREF_RE = re.compile(r"href=[\"']([^\"'#]+)[\"']", re.IGNORECASE)

def tool_url_crawl():
    """Tiny crawler on a single origin. Collect titles + unique paths (cap at 30)."""
    if requests is None:
        cprint("[yellow]requests required:[/] pip install requests")
        return
    start = Prompt.ask("Start URL", default="http://127.0.0.1:8000/") if console else input("Start URL: ")
    try:
        origin = urlparse.urlparse(start)
        origin_netloc = origin.netloc
        scheme = origin.scheme
    except Exception:
        cprint("[red]Invalid URL[/]")
        return
    seen: set[str] = set()
    queue: List[str] = [start]
    rows = []
    while queue and len(seen) < 30:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            r = requests.get(url, timeout=5)
        except Exception:
            continue
        m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE|re.DOTALL)
        title = (m.group(1).strip() if m else '')
        rows.append((url, r.status_code, title))
        for link in HREF_RE.findall(r.text):
            new = urlparse.urljoin(url, link)
            pr = urlparse.urlparse(new)
            if pr.scheme == scheme and pr.netloc == origin_netloc:
                if pr.fragment:
                    new = new.split('#',1)[0]
                if new not in seen and len(queue) < 200:
                    queue.append(new)
    table = Table(title=f"Crawl results ({len(rows)} pages)", box=box.SIMPLE)
    table.add_column("URL", overflow="fold")
    table.add_column("Status")
    table.add_column("Title", overflow="fold")
    for u,s,t in rows:
        table.add_row(u, str(s), t)
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("crawl", [{"url":u, "status":s, "title":t} for u,s,t in rows])
        cprint(f"[green]Saved[/] {p}")


# Add 21–25 to menu
TOOLS.extend([
    Tool("21", "HTTP Security Headers", "Audit common security headers on a URL", tool_http_sec_headers),
    Tool("22", "Traceroute (scapy)", "Discover path to host (needs scapy/root)", tool_traceroute),
    Tool("23", "ARP Scan (local)", "Find live hosts via ARP (needs sudo)", tool_arp_scan),
    Tool("24", "HTTP Dir Enum", "Bruteforce common paths on a site", tool_http_dir_enum),
    Tool("25", "Mini Crawler", "Crawl up to 30 pages on same origin", tool_url_crawl),
])

# ---------- Extra Tools 26–30 ----------

def tool_ssl_expiry_monitor():
    """Check TLS expiry for one or more hostnames."""
    hosts_s = Prompt.ask("Domains (comma)", default="example.com,google.com") if console else input("Domains: ")
    port = int(Prompt.ask("Port", default="443")) if console else int(input("Port: ") or 443)
    hosts = [h.strip() for h in hosts_s.split(",") if h.strip()]
    table = Table(title=f"TLS Expiry (port {port})", box=box.MINIMAL)
    table.add_column("Host")
    table.add_column("Valid To")
    table.add_column("Days Left")
    payload = []
    for host in hosts:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
            exp = cert.get("notAfter")
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(exp)
            days_left = (dt - datetime.utcnow().replace(tzinfo=dt.tzinfo)).days
            table.add_row(host, dt.isoformat(), str(days_left))
            payload.append({"host": host, "valid_to": dt.isoformat(), "days_left": days_left})
        except Exception as e:
            table.add_row(host, "<error>", str(e))
            payload.append({"host": host, "error": str(e)})
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("tls-expiry", payload)
        cprint(f"[green]Saved[/] {p}")


def tool_bulk_ping_sweep():
    """ICMP ping sweep for a small range (uses system ping; cross-platform-ish)."""
    cidr = Prompt.ask("CIDR (small, e.g. 192.168.1.0/28)", default="192.168.1.0/28") if console else input("CIDR: ")
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())[:4096]
    except Exception:
        cprint("[red]Invalid CIDR[/]")
        return
    table = Table(title=f"Ping Sweep {cidr}", box=box.SIMPLE)
    table.add_column("Host")
    table.add_column("Reachable")
    import subprocess, platform
    ping_cmd = ["ping", "-c", "1", "-W", "1"] if platform.system() != "Windows" else ["ping", "-n", "1", "-w", "1000"]
    for h in hosts:
        try:
            ok = subprocess.run(ping_cmd + [str(h)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        except Exception:
            ok = False
        table.add_row(str(h), "✅" if ok else "❌")
    cprint(table)


def tool_public_ip_geo():
    """Show your public IP and rough geo (ip-api.com)."""
    if requests is None:
        cprint("[yellow]requests required:[/] pip install requests")
        return
    try:
        r = requests.get("http://ip-api.com/json/", timeout=6)
        data = r.json()
        table = Table(title="Public IP & Geo", box=box.MINIMAL)
        table.add_column("Field")
        table.add_column("Value")
        for k in ["query","isp","org","country","regionName","city","zip","lat","lon","timezone"]:
            table.add_row(k, str(data.get(k, "")))
        cprint(table)
        if Confirm.ask("Save JSON?", default=False):
            p = save_json_report("public-ip-geo", data)
            cprint(f"[green]Saved[/] {p}")
    except Exception as e:
        cprint(f"[red]Lookup failed:[/] {e}")


IOC_URL_RE  = re.compile(r"https?://[a-zA-Z0-9\.\-_/~%?=&+#:]+")
IOC_IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IOC_EMAIL_RE= re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

def tool_ioc_extract_text():
    """Extract URLs, IPs, and emails from a text file or pasted text."""
    src = Prompt.ask("Source (file path or 'paste')", default="paste") if console else input("Source: ") or "paste"
    if src.lower() == "paste":
        text = Prompt.ask("Paste text (end with Enter)") if console else input("Text: ")
    else:
        try:
            text = Path(src).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            cprint(f"[red]Read failed:[/] {e}")
            return
    urls  = sorted(set(m.group(0) for m in IOC_URL_RE.finditer(text)))
    ips   = sorted(set(m.group(0) for m in IOC_IP_RE.finditer(text)))
    emails= sorted(set(m.group(0) for m in IOC_EMAIL_RE.finditer(text)))
    table = Table(title="IOC Extract", box=box.SIMPLE)
    table.add_column("Type")
    table.add_column("Value", overflow="fold")
    for u in urls[:50]:
        table.add_row("URL", u)
    for i in ips[:50]:
        table.add_row("IP", i)
    for e in emails[:50]:
        table.add_row("Email", e)
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("ioc-extract", {"urls": urls, "ips": ips, "emails": emails})
        cprint(f"[green]Saved[/] {p}")


SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})", "AWS Secret (config)"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,48}", "Slack token"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe live secret"),
    (r"ssh-rsa\\s+[A-Za-z0-9/+]{100,}={0,3}", "SSH RSA public key"),
]

def tool_secret_scan():
    """Scan a directory for common API keys/tokens (regex-based; local only)."""
    root = Path(Prompt.ask("Path to scan", default=str(Path.cwd()))) if console else Path(input("Path: ") or str(Path.cwd()))
    exts = set(x.strip().lower() for x in (Prompt.ask("Extensions (comma, blank=all)", default="py,js,ts,env,json,txt,yml,yaml") if console else input("Exts: ") or "py,js,ts,env,json,txt,yml,yaml").split(",") if x.strip())
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and (not exts or p.suffix.lower().lstrip(".") in exts)]
    findings = []
    for f in files[:5000]:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pat, label in SECRET_PATTERNS:
            for m in re.finditer(pat, text):
                findings.append({"path": str(f), "match": m.group(0)[:80], "type": label})
    table = Table(title=f"Secret Scan ({len(findings)} hits)", box=box.SIMPLE)
    table.add_column("File", overflow="fold")
    table.add_column("Type")
    table.add_column("Preview", overflow="fold")
    for it in findings[:200]:
        table.add_row(it["path"], it["type"], it["match"])
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("secret-scan", findings)
        cprint(f"[green]Saved[/] {p}")

# Add 26–30 to menu
TOOLS.extend([
    Tool("26", "TLS Expiry Monitor", "Days until cert expiry for domains", tool_ssl_expiry_monitor),
    Tool("27", "Bulk Ping Sweep", "Ping a small CIDR range", tool_bulk_ping_sweep),
    Tool("28", "Public IP + Geo", "Show your public IP & rough geo", tool_public_ip_geo),
    Tool("29", "IOC Extract (text)", "Extract URLs, IPs, emails from text", tool_ioc_extract_text),
    Tool("30", "Secret Scan (regex)", "Find common API keys/tokens in files", tool_secret_scan),
])

# ---------- NEW SOCIAL / PHONE / UTIL TOOLS 31–38 ----------

def tool_phone_intel():
    """Deep phone intel: validity, type, E164/international/national, country & region, carrier, timezones, NDC/NSN."""
    if phonenumbers is None:
        cprint("[yellow]phonenumbers required:[/] pip install phonenumbers")
        return
    raw = Prompt.ask("Number(s), comma-sep (e.g. +12025550123, 2025550123)") if console else input("Numbers: ")
    default_region = Prompt.ask("Default region (2-letter, e.g. US) if no +country", default="US") if console else (input("Default region (e.g. US): ") or "US")
    nums = [x.strip() for x in (raw or "").split(",") if x.strip()]

    table = Table(title="Phone Intelligence", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Input")
    table.add_column("Valid")
    table.add_column("Type")
    table.add_column("Region")
    table.add_column("Carrier")
    table.add_column("TZ")
    table.add_column("E164", overflow="fold")
    table.add_column("International", overflow="fold")
    table.add_column("National", overflow="fold")

    payload = []
    for n in nums:
        rec = {"input": n}
        try:
            pn = phonenumbers.parse(n, default_region)
            valid = phonenumbers.is_valid_number(pn)
            rec["valid"] = valid
            ntype = phonenumbers.number_type(pn)
            tmap = {
                phonenumbers.PhoneNumberType.FIXED_LINE: "fixed",
                phonenumbers.PhoneNumberType.MOBILE: "mobile",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed/mobile",
                phonenumbers.PhoneNumberType.TOLL_FREE: "toll-free",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium",
                phonenumbers.PhoneNumberType.SHARED_COST: "shared",
                phonenumbers.PhoneNumberType.VOIP: "voip",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal",
                phonenumbers.PhoneNumberType.PAGER: "pager",
                phonenumbers.PhoneNumberType.UAN: "uan",
                phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
                phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
            }
            rec["type"] = tmap.get(ntype, "unknown")
            rec["region"] = phone_geocoder.description_for_number(pn, "en") if phone_geocoder else ""
            rec["carrier"] = phone_carrier.name_for_number(pn, "en") if phone_carrier else ""
            rec["tzs"] = list(phone_timezone.time_zones_for_number(pn)) if phone_timezone else []
            # Formats
            rec["e164"] = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164) if valid else ""
            rec["intl"] = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL) if valid else ""
            rec["natl"] = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL) if valid else ""
            # Country code & NSN (National Significant Number) granularity
            rec["country_code"] = pn.country_code
            rec["nsn"] = phonenumbers.national_significant_number(pn)
            # NDC (geographic area or service provider prefix) guess:
            try:
                ndc_len = phonenumbers.length_of_national_destination_code(pn)
                rec["ndc"] = rec["nsn"][:ndc_len] if ndc_len > 0 else ""
                rec["subscriber_number"] = rec["nsn"][ndc_len:] if ndc_len > 0 else rec["nsn"]
            except Exception:
                rec["ndc"] = ""
                rec["subscriber_number"] = rec["nsn"]

            table.add_row(
                n,
                "✅" if valid else "❌",
                rec["type"],
                rec["region"] or "-",
                rec["carrier"] or "-",
                ", ".join(rec["tzs"]) or "-",
                rec["e164"] or "-",
                rec["intl"] or "-",
                rec["natl"] or "-",
            )
        except Exception as e:
            rec["error"] = str(e)
            table.add_row(n, "❌", "-", "-", "-", "-", "-", "-", "-")
        payload.append(rec)

    cprint(table)
    if Confirm.ask("Show detailed fields?", default=False):
        dt = Table(title="Phone Details", box=box.SIMPLE)
        dt.add_column("Field")
        dt.add_column("Value", overflow="fold")
        for rec in payload:
            dt.add_row("—", f"[bold]{rec['input']}[/]")
            for k in ("country_code","nsn","ndc","subscriber_number"):
                if rec.get(k) not in (None, ""):
                    dt.add_row(k, str(rec[k]))
        cprint(dt)

    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("phone-intel-extended", payload)
        cprint(f"[green]Saved[/] {p}")

# ---------- STRONGER: Discord / Telegram / Phone ----------
def tool_discord_bulk_extract():
    """Extract Discord snowflakes, invites, webhooks, message links, and mentions from pasted text (Offline)."""
    text = Prompt.ask("Paste text") if console else input("Text: ")
    finds = {
        "snowflakes": sorted(set(re.findall(r"(?<!\d)(\d{16,20})(?!\d)", text))),
        "invites": sorted(set(m.group(0) for m in DISCORD_URL_PATTERNS["invite"].finditer(text))),
        "webhooks": sorted(set(m.group(0) for m in DISCORD_URL_PATTERNS["webhook"].finditer(text))),
        "messages": sorted(set(m.group(0) for m in DISCORD_URL_PATTERNS["message"].finditer(text))),
        "mentions_user": sorted(set(m.group(0) for m in re.finditer(r"<@!?\d+>", text))),
        "mentions_role": sorted(set(m.group(0) for m in re.finditer(r"<@&\d+>", text))),
        "emojis": sorted(set(m.group(0) for m in re.finditer(r"<a?:[A-Za-z0-9_]{2,32}:\d+>", text))),
    }
    table = Table(title="Discord Bulk Extract", box=box.SIMPLE)
    table.add_column("Type")
    table.add_column("Count")
    table.add_column("Samples", overflow="fold")
    for k, vals in finds.items():
        table.add_row(k, str(len(vals)), ", ".join(vals[:5]))
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("discord-bulk-extract", finds)
        cprint(f"[green]Saved[/] {p}")


def tool_telegram_bulk_extract():
    """Extract Telegram usernames, joinchat invites, message links, and proxies from pasted text (Offline)."""
    text = Prompt.ask("Paste text") if console else input("Text: ")
    usernames = sorted(set(m.group(1) for m in re.finditer(r"(?<!\w)@([A-Za-z0-9_]{5,32})", text)))
    links = sorted(set(m.group(0) for m in re.finditer(r"https?://(?:t\.me|telegram\.me|telegram\.dog)/[^\s)>\]]+", text)))
    joinchat = [u for u in links if "/joinchat/" in u or "/+" in u]
    proxies = [u for u in links if "/socks" in u or "/proxy" in u]
    posts = []
    for u in links:
        try:
            pu = urlparse.urlparse(u)
            parts = pu.path.strip("/").split("/")
            if parts and len(parts) >= 2 and parts[1].isdigit():
                posts.append(u)
        except Exception:
            pass
    table = Table(title="Telegram Bulk Extract", box=box.SIMPLE)
    table.add_column("Type")
    table.add_column("Count")
    table.add_column("Samples", overflow="fold")
    table.add_row("usernames", str(len(usernames)), ", ".join(("@" + x) for x in usernames[:5]))
    table.add_row("links", str(len(links)), ", ".join(links[:5]))
    table.add_row("joinchat/invite", str(len(joinchat)), ", ".join(joinchat[:5]))
    table.add_row("posts", str(len(posts)), ", ".join(posts[:5]))
    table.add_row("proxies", str(len(proxies)), ", ".join(proxies[:5]))
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("telegram-bulk-extract", {
            "usernames": usernames, "links": links, "invites": joinchat, "posts": posts, "proxies": proxies
        })
        cprint(f"[green]Saved[/] {p}")

DISCORD_URL_PATTERNS = {
    "message": re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/channels/(\d+|@me)/(\d+)/(\d+)"),
    "channel": re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/channels/(\d+|@me)/(\d+)/?$"),
    "user": re.compile(r"^<@!?(\d+)>$"),
    "role": re.compile(r"^<@&(\d+)>$"),
    "emoji": re.compile(r"^<a?:([a-zA-Z0-9_]{2,32}):(\d+)>$"),
    "webhook": re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(\d+)/([A-Za-z0-9_\-\.]+)"),
    "invite": re.compile(r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite)/([A-Za-z0-9\-]+)"),
    "cdn_asset": re.compile(r"https?://cdn\.discordapp\.com/(?:avatars|icons|emojis|banners)/([A-Za-z0-9]+)/([A-Za-z0-9]+)\.(?:png|jpg|jpeg|webp|gif)"),
    "attachment": re.compile(r"https?://cdn\.discordapp\.com/attachments/(\d+)/(\d+)/([^?\s]+)"),
    "thread": re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/channels/(\d+)/(\d+)/(\d+)"),
    "guild_template": re.compile(r"https?://discord(?:app)?\.com/template/([A-Za-z0-9\-]+)"),
}

def _discord_snowflake_to_dt(snow: int) -> datetime:
    epoch_ms = 1420070400000  # 2015-01-01T00:00:00Z
    ts_ms = (snow >> 22) + epoch_ms
    return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)

def _analyze_snowflake(s: int) -> dict:
    return {
        "snowflake": str(s),
        "utc_time": _discord_snowflake_to_dt(s).isoformat(),
        "worker_id": (s & 0x3E0000) >> 17,
        "process_id": (s & 0x1F000) >> 12,
        "increment": s & 0xFFF,
    }

def tool_discord_snowflake():
    """Decode Discord snowflakes & links → timestamps, IDs, component bits, and URL context. (Offline-only)"""
    raw = Prompt.ask("Snowflake / Discord URL / mention") if console else input("Snowflake/URL: ")
    sraw = raw.strip()

    rows = []
    meta = {"input": sraw}

    # Quick multi-pattern pass
    matched = False
    for name, rx in DISCORD_URL_PATTERNS.items():
        m = rx.search(sraw)
        if not m:
            continue
        matched = True
        meta["pattern"] = name

        if name in {"message", "thread"}:
            guild_id, channel_id, msg_id = m.groups()
            meta.update({"guild_id": guild_id, "channel_id": channel_id, "message_id": msg_id})
            # Decode IDs if numeric
            for label, sid in [("guild_id", guild_id), ("channel_id", channel_id), ("message_id", msg_id)]:
                if sid.isdigit():
                    info = _analyze_snowflake(int(sid))
                    for k, v in info.items():
                        rows.append((f"{label}.{k}", str(v)))
            break

        if name == "channel":
            guild_id, channel_id = m.groups()
            meta.update({"guild_id": guild_id, "channel_id": channel_id})
            for label, sid in [("guild_id", guild_id), ("channel_id", channel_id)]:
                if sid.isdigit():
                    info = _analyze_snowflake(int(sid))
                    for k, v in info.items():
                        rows.append((f"{label}.{k}", str(v)))
            break

        if name == "user":
            user_id = m.group(1)
            meta["user_id"] = user_id
            info = _analyze_snowflake(int(user_id))
            for k, v in info.items():
                rows.append((f"user.{k}", str(v)))
            break

        if name == "role":
            role_id = m.group(1)
            meta["role_id"] = role_id
            info = _analyze_snowflake(int(role_id))
            for k, v in info.items():
                rows.append((f"role.{k}", str(v)))
            break

        if name == "emoji":
            name_, emoji_id = m.groups()
            meta["emoji_name"] = name_
            meta["emoji_id"] = emoji_id
            info = _analyze_snowflake(int(emoji_id))
            for k, v in info.items():
                rows.append((f"emoji.{k}", str(v)))
            break

        if name == "webhook":
            wid, token = m.groups()
            meta["webhook_id"] = wid
            # redaction of secret token, but show prefix/suffix length
            red = token[:6] + "…" + token[-4:] if len(token) > 12 else "redacted"
            meta["webhook_token_preview"] = red
            if wid.isdigit():
                info = _analyze_snowflake(int(wid))
                for k, v in info.items():
                    rows.append((f"webhook.{k}", str(v)))
            break

        if name == "invite":
            code = m.group(1)
            meta["invite_code"] = code
            meta["looks_like_vanity"] = "yes" if "-" in code or len(code) < 7 else "no"
            rows.append(("invite.code_length", str(len(code))))
            break

        if name == "cdn_asset":
            parent_id, asset_id = m.groups()
            meta.update({"cdn_parent_id": parent_id, "cdn_asset_id": asset_id})
            # asset_id may not be snowflake; skip decode
            rows.append(("cdn.parent_id", parent_id))
            rows.append(("cdn.asset_id", asset_id))
            break

        if name == "attachment":
            chan_id, msg_id, filename = m.groups()
            meta.update({"attachment_channel_id": chan_id, "attachment_message_id": msg_id, "filename": filename})
            for label, sid in [("channel_id", chan_id), ("message_id", msg_id)]:
                if sid.isdigit():
                    info = _analyze_snowflake(int(sid))
                    for k, v in info.items():
                        rows.append((f"attachment.{label}.{k}", str(v)))
            rows.append(("attachment.filename", filename))
            break

        if name == "guild_template":
            meta["guild_template"] = m.group(1)
            rows.append(("template.code_length", str(len(meta["guild_template"]))))
            break

    # If not pattern, try any numeric snowflake in the input
    if not matched:
        num = re.sub(r"[^\d]", "", sraw)
        if num:
            try:
                info = _analyze_snowflake(int(num))
                meta["interpreted_as"] = "snowflake"
                for k, v in info.items():
                    rows.append((k, str(v)))
                matched = True
            except Exception:
                pass

    # Mentions inside text (multiple)
    mentions = []
    for rx in (DISCORD_URL_PATTERNS["user"], DISCORD_URL_PATTERNS["role"]):
        for m in rx.finditer(sraw):
            mentions.append(m.group(1))
    if mentions:
        meta["mentions_found"] = len(mentions)
        for i, mid in enumerate(mentions, 1):
            try:
                info = _analyze_snowflake(int(mid))
                for k, v in info.items():
                    rows.append((f"mention[{i}].{k}", str(v)))
            except Exception:
                rows.append((f"mention[{i}].id", mid))

    # Table output
    title = "Discord Analyzer"
    table = Table(title=title, box=box.SIMPLE)
    table.add_column("Field")
    table.add_column("Value", overflow="fold")
    for k in ["input","pattern","interpreted_as","invite_code","looks_like_vanity","webhook_id","webhook_token_preview",
              "guild_id","channel_id","message_id","user_id","role_id","emoji_name","emoji_id",
              "attachment_channel_id","attachment_message_id","filename","cdn_parent_id","cdn_asset_id",
              "guild_template","mentions_found"]:
        if meta.get(k) not in (None, ""):
            table.add_row(k, str(meta[k]))
    for k, v in rows:
        table.add_row(k, v)
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        payload = {"meta": meta, "rows": rows}
        p = save_json_report("discord-analyze", payload)
        cprint(f"[green]Saved[/] {p}")


def tool_discord_invite_parse():
    """Parse Discord invite codes/URLs (no API calls)."""
    raw = Prompt.ask("Invite (discord.gg/... or code)") if console else input("Invite/code: ")
    code = raw.strip()
    m = re.search(r"(?:discord\.gg/|discord(?:app)?\.com/invite/)([A-Za-z0-9\-]+)", code)
    if m:
        code = m.group(1)
    vanity = "-" in code or len(code) < 7
    table = Table(title="Discord Invite", box=box.SIMPLE)
    table.add_column("Field"); table.add_column("Value")
    table.add_row("code", code)
    table.add_row("looks_like_vanity", "Yes" if vanity else "No")
    table.add_row("length", str(len(code)))
    cprint(table)
    cprint("[dim]Note: This is offline parsing only; no Discord API is called.[/]")

TELEGRAM_HOSTS = {"t.me", "telegram.me", "telegram.dog"}
def tool_telegram_link_parse():
    """Parse Telegram handles/links: usernames, channels, invite codes, posts, deep-link params, proxies (Offline)."""
    raw = Prompt.ask("Telegram handle/link (@user | https://t.me/...)") if console else input("Telegram: ")
    s = raw.strip()
    info = {"input": s}

    def add_row(rows, k, v): rows.append((k, str(v)))

    rows = []
    if s.startswith("@"):
        info["type"] = "username"
        info["username"] = s[1:]
        add_row(rows, "username.length", len(info["username"]))
    else:
        try:
            u = urlparse.urlparse(s)
        except Exception:
            u = None
        if u and u.netloc.lower() in TELEGRAM_HOSTS:
            path = u.path.strip("/")
            qs = dict(urlparse.parse_qsl(u.query))
            parts = path.split("/") if path else []
            # Common shapes
            if not parts:
                info["type"] = "root"
            elif parts[0] in {"joinchat", "+", "addstickers", "addtheme"}:
                info["type"] = parts[0]
                info["code_or_name"] = parts[1] if len(parts) > 1 else ""
            elif parts[0] == "c":  # numeric channel (supergroup) + optional msg id
                info["type"] = "channel_id"
                if len(parts) > 1:
                    info["channel_id"] = parts[1]
                if len(parts) > 2 and parts[2].isdigit():
                    info["msg_id"] = parts[2]
            elif parts[0] in {"socks", "proxy"}:
                info["type"] = "proxy"
                info["query"] = qs
            else:
                # public username + optional post id
                info["type"] = "username"
                info["username"] = parts[0]
                if len(parts) > 1 and parts[1].isdigit():
                    info["msg_id"] = parts[1]
            # deeplink params
            for key in ("start", "startapp", "startattach", "game", "voicechat"):
                if key in qs:
                    info[f"deeplink.{key}"] = qs[key]
        else:
            info["type"] = "unknown"

    # Output
    table = Table(title="Telegram Analyzer", box=box.SIMPLE)
    table.add_column("Field")
    table.add_column("Value", overflow="fold")
    for k, v in info.items():
        table.add_row(k, str(v))
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("telegram-analyze", {"info": info})
        cprint(f"[green]Saved[/] {p}")

def tool_qr_make():
    """Generate a QR code PNG for text/URL."""
    if qrcode is None or Image is None:
        cprint("[yellow]qrcode & pillow required:[/] pip install qrcode[pil] Pillow")
        return
    data = Prompt.ask("Text/URL to encode") if console else input("Text: ")
    out = Prompt.ask("Output filename", default=str(REPORTS_DIR / "qrcode.png")) if console else (input("Output file: ") or str(REPORTS_DIR / "qrcode.png"))
    try:
        img = qrcode.make(data)
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        img.save(out)
        cprint(f"[green]Saved QR code to[/] {out}")
    except Exception as e:
        cprint(f"[red]QR generation failed:[/] {e}")


def tool_url_analyzer():
    """Parse a URL into components + query params; optionally paste headers to extract cookies."""
    raw = Prompt.ask("URL") if console else input("URL: ")
    try:
        u = urlparse.urlparse(raw)
    except Exception as e:
        cprint(f"[red]Invalid URL:[/] {e}")
        return
    table = Table(title="URL Components", box=box.SIMPLE)
    table.add_column("Part"); table.add_column("Value", overflow="fold")
    parts = {
        "scheme": u.scheme, "netloc": u.netloc, "path": u.path, "params": u.params,
        "query": u.query, "fragment": u.fragment, "username": u.username,
        "password": "***" if u.password else "", "hostname": u.hostname, "port": u.port
    }
    for k,v in parts.items():
        table.add_row(k, str(v) if v is not None else "")
    cprint(table)
    if u.query:
        q = urlparse.parse_qs(u.query, keep_blank_values=True)
        tq = Table(title="Query Parameters", box=box.MINIMAL)
        tq.add_column("Key"); tq.add_column("Values", overflow="fold")
        for k,v in q.items():
            tq.add_row(k, ", ".join(v))
        cprint(tq)
    if Confirm.ask("Paste raw HTTP response headers to extract Set-Cookie? (y/N)", default=False):
        headers_text = Prompt.ask("Paste headers (end with Enter)") if console else input("Headers: ")
        cookies = []
        for line in headers_text.splitlines():
            if line.lower().startswith("set-cookie:"):
                cookies.append(line.split(":",1)[1].strip())
        if cookies:
            tk = Table(title="Cookies", box=box.SIMPLE)
            tk.add_column("Set-Cookie", overflow="fold")
            for c in cookies:
                tk.add_row(c)
            cprint(tk)


def tool_file_entropy():
    """Compute Shannon entropy of a file to spot random/encrypted data."""
    path = Prompt.ask("File path") if console else input("File: ")
    p = Path(path)
    if not p.exists() or not p.is_file():
        cprint("[red]File not found[/]")
        return
    data = p.read_bytes()
    if not data:
        cprint("[yellow]Empty file[/]")
        return
    from collections import Counter
    freq = Counter(data)
    total = len(data)
    ent = -sum((c/total) * math.log2(c/total) for c in freq.values())
    cprint(Panel.fit(f"Size: {total} bytes\nShannon entropy: {ent:.3f} bits/byte\n(≈8.0 → random/encrypted, <5.0 → structured)", title=str(p)))


def tool_hash_id():
    """Guess hash algorithm by length/prefix (quick heuristic)."""
    h = Prompt.ask("Hash string") if console else input("Hash: ")
    s = h.strip().lower()
    guess = []
    if re.fullmatch(r"[a-f0-9]{32}", s):
        guess.append("MD5 (32 hex)")
    if re.fullmatch(r"[a-f0-9]{40}", s):
        guess.append("SHA1 (40 hex)")
    if re.fullmatch(r"[a-f0-9]{56}", s):
        guess.append("SHA224 (56 hex)")
    if re.fullmatch(r"[a-f0-9]{64}", s):
        guess.append("SHA256 (64 hex)")
    if re.fullmatch(r"[a-f0-9]{96}", s):
        guess.append("SHA384 (96 hex)")
    if re.fullmatch(r"[a-f0-9]{128}", s):
        guess.append("SHA512 (128 hex)")
    if s.startswith("$2a$") or s.startswith("$2b$") or s.startswith("$2y$"):
        guess.append("bcrypt (modular crypt)")
    if s.startswith("$argon2"):
        guess.append("Argon2")
    if s.startswith("$6$"):
        guess.append("SHA512-crypt")
    if not guess:
        guess.append("Unknown/other")
    table = Table(title="Hash Guess", box=box.SIMPLE)
    table.add_column("Guess")
    for g in guess:
        table.add_row(g)
    cprint(table)


def tool_base_convert():
    """Convert numbers between hex/dec/bin."""
    raw = Prompt.ask("Number (e.g. 255, 0xff, 0b1111)") if console else input("Number: ")
    s = raw.strip().lower()
    try:
        if s.startswith("0x"):
            n = int(s, 16)
        elif s.startswith("0b"):
            n = int(s, 2)
        else:
            n = int(s, 10)
        table = Table(title="Base Convert", box=box.SIMPLE)
        table.add_column("Base"); table.add_column("Value")
        table.add_row("dec", str(n))
        table.add_row("hex", hex(n))
        table.add_row("bin", bin(n))
        cprint(table)
    except Exception as e:
        cprint(f"[red]Parse error:[/] {e}")


# Add 31–38 to menu
TOOLS.extend([
    Tool("31", "Phone Intel", "Parse/validate phone numbers (carrier/region/tz)", tool_phone_intel),
    Tool("32", "Discord Snowflake", "Decode snowflake or message URL → time", tool_discord_snowflake),
    Tool("33", "Discord Invite Parse", "Offline parser for discord invites", tool_discord_invite_parse),
    Tool("34", "Telegram Link Parse", "Parse t.me links (user/channel/invite)", tool_telegram_link_parse),
    Tool("35", "QR Code Maker", "Generate a QR PNG for text/URLs", tool_qr_make),
    Tool("36", "URL Analyzer", "Break down URL + params (+cookies)", tool_url_analyzer),
    Tool("37", "File Entropy", "Shannon entropy of a file", tool_file_entropy),
    Tool("38", "Hash ID (quick)", "Heuristic guess of hash algorithm", tool_hash_id),
    Tool("39", "Base Convert", "Hex/dec/bin converter", tool_base_convert),
])
TOOLS.extend([
    Tool("40", "Discord Bulk Extract", "Find snowflakes/invites/webhooks/mentions in text", tool_discord_bulk_extract),
    Tool("41", "Telegram Bulk Extract", "Find usernames/invites/posts/proxies in text", tool_telegram_bulk_extract),
])

def _dns_txt(name: str) -> List[str]:
    out = []
    if dns and hasattr(dns, "resolver"):
        try:
            for r in dns.resolver.resolve(name, "TXT"):
                out.append(b"".join(r.strings).decode("utf-8", errors="ignore"))
        except Exception:
            pass
    return out

def _dns_mx(name: str) -> List[str]:
    out = []
    if dns and hasattr(dns, "resolver"):
        try:
            for r in dns.resolver.resolve(name, "MX"):
                out.append(str(r.exchange).rstrip("."))
        except Exception:
            pass
    return out

def tool_email_auth():
    """Check domain's email auth: MX, SPF, DMARC (DNS)."""
    domain = Prompt.ask("Domain", default="example.com") if console else input("Domain: ")
    mx = _dns_mx(domain)
    spf = [t for t in _dns_txt(domain) if t.lower().startswith("v=spf1")]
    dmarc = [t for t in _dns_txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    table = Table(title=f"Email Auth — {domain}", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Record")
    table.add_column("Value", overflow="fold")
    table.add_row("MX", ", ".join(mx) or "<none>")
    table.add_row("SPF", "; ".join(spf) or "<none>")
    table.add_row("DMARC", "; ".join(dmarc) or "<none>")
    cprint(table)
    if dmarc:
        pol = re.search(r"p=([a-zA-Z]+)", dmarc[0])
        rua = re.search(r"rua=([^;]+)", dmarc[0])
        dt = Table(title="DMARC Details", box=box.SIMPLE)
        dt.add_column("Field"); dt.add_column("Value", overflow="fold")
        if pol: dt.add_row("policy", pol.group(1))
        if rua: dt.add_row("rua", rua.group(1))
        cprint(dt)

TOOLS.append(Tool("42", "Email Auth Check", "MX / SPF / DMARC via DNS", tool_email_auth))

OPEN_REDIRECT_KEYS = {"next","url","redirect","redirect_url","redirect_uri","return","returnTo","dest","destination","goto","to"}

def tool_open_redirect_hunter():
    """Scan URLs for suspicious redirect parameters (pattern-based)."""
    raw = Prompt.ask("URLs (comma)") if console else input("URLs: ")
    urls = [u.strip() for u in raw.split(",") if u.strip()]
    table = Table(title="Open Redirect Param Hunter", box=box.SIMPLE)
    table.add_column("URL", overflow="fold")
    table.add_column("Suspicious Params")
    for u in urls:
        try:
            pr = urlparse.urlparse(u)
            q = urlparse.parse_qs(pr.query, keep_blank_values=True)
            suspects = [k for k in q if k.lower() in OPEN_REDIRECT_KEYS]
            table.add_row(u, ", ".join(suspects) or "-")
        except Exception as e:
            table.add_row(u, f"ERR: {e}")
    cprint(table)

TOOLS.append(Tool("43", "Open-Redirect Hunter", "Flags suspicious redirect params", tool_open_redirect_hunter))

try:
    import mmh3
except Exception:
    mmh3 = None

def tool_favicon_hash():
    """Download /favicon.ico and print mmh3 hash (Shodan-style)."""
    if requests is None:
        cprint("[yellow]requests required:[/] pip install requests")
        return
    if mmh3 is None:
        cprint("[yellow]mmh3 required:[/] pip install mmh3")
        return
    url = Prompt.ask("Site (scheme+host)", default="https://example.com") if console else input("Site: ")
    fav = url.rstrip("/") + "/favicon.ico"
    try:
        r = requests.get(fav, timeout=8)
        if r.status_code != 200:
            cprint(f"[red]HTTP {r.status_code}[/] from {fav}")
            return
        b64 = base64.b64encode(r.content).decode()
        h = mmh3.hash(b64)
        table = Table(title="Favicon Hash", box=box.SIMPLE)
        table.add_column("Field"); table.add_column("Value", overflow="fold")
        table.add_row("URL", fav)
        table.add_row("mmh3", str(h))
        cprint(table)
    except Exception as e:
        cprint(f"[red]Fetch failed:[/] {e}")

TOOLS.append(Tool("44", "Favicon Hash (mmh3)", "Shodan-friendly favicon signature", tool_favicon_hash))

try:
    import magic as filemagic
except Exception:
    filemagic = None

def tool_file_magic_strings():
    """Identify file type (libmagic) and extract printable strings (cap)."""
    path = Prompt.ask("File path") if console else input("File: ")
    p = Path(path)
    if not p.exists() or not p.is_file():
        cprint("[red]File not found[/]")
        return
    table = Table(title="File Magic", box=box.SIMPLE)
    table.add_column("Field"); table.add_column("Value", overflow="fold")
    if filemagic is None:
        table.add_row("magic", "python-magic not installed (pip install python-magic)")
    else:
        try:
            ms = filemagic.Magic(mime=False)
            table.add_row("magic", ms.from_file(str(p)))
        except Exception as e:
            table.add_row("magic", f"ERR: {e}")
    data = p.read_bytes()
    # printable strings (like 'strings')
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13):
            cur.append(b)
            if len(cur) > 4096:  # avoid absurdly long lines
                out.append(cur.decode(errors="ignore"))
                cur = bytearray()
        else:
            if len(cur) >= 4:
                out.append(cur.decode(errors="ignore"))
            cur = bytearray()
    if len(cur) >= 4: out.append(cur.decode(errors="ignore"))
    preview = "\n".join(out[:80])
    cprint(table)
    cprint(Panel.fit(preview or "<no strings>", title="strings (first 80)", box=box.ROUNDED))

TOOLS.append(Tool("45", "File Magic + strings", "libmagic type + printable strings", tool_file_magic_strings))

try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None


def _clean_path_input(s: str) -> Path:
    s = (s or "").strip().strip("'\"")
    return Path(s).expanduser()

def tool_pdf_meta():
    """Read PDF metadata & page count robustly (pypdf -> pdfminer fallback)."""
    raw = Prompt.ask("PDF path") if console else input("PDF path: ")
    p = _clean_path_input(raw)
    if not p.exists() or not p.is_file():
        cprint("[red]Not found[/] — " + str(p))
        return

    meta_rows = []     # (key, value)
    payload   = {}
    pages     = None
    enc       = False
    title     = None
    producer  = None

    # Try pypdf first
    pypdf_ok = False
    if 'PYPDF_Reader' in globals() and PYPDF_Reader is not None:
        try:
            reader = PYPDF_Reader(str(p))
            enc = bool(getattr(reader, "is_encrypted", False))
            if enc:
                try:
                    reader.decrypt("")
                except Exception:
                    pass
            pages = len(reader.pages)
            md = reader.metadata or {}
            for k, v in (md.items() if hasattr(md, "items") else []):
                key = k[1:] if isinstance(k, str) and k.startswith('/') else str(k)
                val = "" if v is None else str(v)
                meta_rows.append((key, val))
                payload[key] = val
            title = payload.get("Title") or payload.get("title")
            producer = payload.get("Producer") or payload.get("producer")
            pypdf_ok = True
        except Exception as e:
            cprint(f"[yellow]pypdf parse failed:[/] {e}")

    # Fallback: pdfminer.six
    if (not pypdf_ok) and all(x in globals() and globals()[x] is not None for x in ("PDFParser","PDFDocument")):
        try:
            with open(p, "rb") as fh:
                parser = PDFParser(fh)
                doc = PDFDocument(parser)
                pages_node = doc.catalog.get("Pages")

                def _count_pages(node, cap=5000):
                    try:
                        if not isinstance(node, dict):
                            return 0
                        if "Count" in node:
                            return int(node.get("Count", 0))
                        kids = node.get("Kids", []) or []
                        total = 0
                        for kid in kids[:cap]:
                            total += _count_pages(kid, cap)
                        return total
                    except Exception:
                        return 0
                try:
                    pages = _count_pages(pages_node) or (pages_node.get("Count") if isinstance(pages_node, dict) else None)
                except Exception:
                    pass

                info_list = getattr(doc, "info", []) or []
                merged = {}
                for d in info_list:
                    for k, v in (d.items() if hasattr(d, "items") else []):
                        kk = k.decode("utf-8","ignore") if isinstance(k,(bytes,bytearray)) else str(k)
                        vv = v.decode("utf-8","ignore") if isinstance(v,(bytes,bytearray)) else str(v)
                        merged[kk.lstrip("/")] = vv
                for k, v in merged.items():
                    meta_rows.append((k, v))
                    payload[k] = v
                title = merged.get("Title") or merged.get("title")
                producer = merged.get("Producer") or merged.get("producer")
        except Exception as e:
            cprint(f"[red]pdfminer parse failed:[/] {e}")

    # Render table (track seen keys instead of indexing rows)
    hdr = f"PDF Meta — {(title.strip() if isinstance(title, str) and title.strip() else p.name)}"
    tbl_kwargs = {}
    if box:
        tbl_kwargs["box"] = box.MINIMAL_DOUBLE_HEAD
    table = Table(title=hdr, **tbl_kwargs)
    table.add_column("Field")
    table.add_column("Value", overflow="fold")

    seen_keys = set()

    def add_row_unique(k: str, v: str):
        key_norm = (k or "").strip().lower()
        if key_norm and key_norm not in seen_keys:
            table.add_row(k, v)
            seen_keys.add(key_norm)

    add_row_unique("pages", str(pages) if pages is not None else "<unknown>")
    payload["pages"] = pages
    add_row_unique("encrypted", "Yes" if enc else "No")
    payload["encrypted"] = enc
    if producer:
        add_row_unique("Producer", producer)
    if title:
        add_row_unique("Title", title)

    for k, v in meta_rows:
        if k:
            add_row_unique(k, v)

    cprint(table)

    if Confirm.ask("Save JSON?", default=False):
        payload.update({
            "file": str(p),
            "name": p.name,
            "checked_utc": datetime.utcnow().isoformat() + "Z",
        })
        out = save_json_report("pdf-meta", payload)
        cprint(f"[green]Saved[/] {out}")

TOOLS.append(Tool("46", "PDF Meta", "Read PDF metadata & page count (robust)", tool_pdf_meta))

try:
    from zxcvbn import zxcvbn
except Exception:
    zxcvbn = None

def tool_pw_strength():
    """Estimate password strength (offline model from zxcvbn)."""
    if zxcvbn is None:
        cprint("[yellow]zxcvbn required:[/] pip install zxcvbn")
        return
    pw = Prompt.ask("Password (input not hidden!)") if console else input("Password: ")
    res = zxcvbn(pw)
    table = Table(title="Password Strength", box=box.SIMPLE)
    table.add_column("Field"); table.add_column("Value", overflow="fold")
    for k in ["score","guesses","guesses_log10"]:
        table.add_row(k, str(res.get(k)))
    feed = res.get("feedback", {})
    if feed.get("warning"):
        table.add_row("warning", feed["warning"])
    if feed.get("suggestions"):
        table.add_row("suggestions", "; ".join(feed["suggestions"]))
    cprint(table)

TOOLS.append(Tool("47", "Password Strength", "zxcvbn offline estimator", tool_pw_strength))

# === DROP-IN ADD-ONS: Discord / Telegram / QR / Utils (Tools 48–55) ===
# Paste this near the bottom of your existing file (before build_cli/main),
# or keep it as a separate module and import the functions + TOOLS extensions.

import base64, string

# --- Helpers ---
def _redact_secret(s: str, keep_head: int = 6, keep_tail: int = 4) -> str:
    if not s:
        return ""
    if len(s) <= keep_head + keep_tail + 1:
        return s[0] + "…" + s[-1]
    return f"{s[:keep_head]}…{s[-keep_tail:]}"

# Safer base64url decode (for Discord token parts)
def _b64url_try(s: str) -> str:
    try:
        pad = (-len(s)) % 4
        s2 = s + ("=" * pad)
        return base64.urlsafe_b64decode(s2.encode()).decode("utf-8", "ignore")
    except Exception:
        return ""

# --- Discord token formats (offline only; no API calls) ---
# User tokens (legacy/new) and MFA tokens. We DO NOT verify them; only parse structure.
DISCORD_TOKEN_PATTERNS = [
    # Legacy/new 3-part tokens like xxxxx.yyyyyy.zzzzzz (base64url chunks)
    re.compile(r"(?<![A-Za-z0-9_\-])([A-Za-z\d_\-]{23,28}\.[A-Za-z\d_\-]{6}\.[A-Za-z\d_\-]{27,68})(?![A-Za-z0-9_\-])"),
    # MFA tokens start with mfa.
    re.compile(r"(?<![A-Za-z0-9_\-])(mfa\.[A-Za-z\d_\-]{60,120})(?![A-Za-z0-9_\-])"),
]

# Bot tokens: BASE64(snowflake):<secret>
DISCORD_BOT_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_\-])([A-Za-z\d_\-]{20,50}:[A-Za-z0-9_\-]{20,100})(?![A-Za-z0-9_\-])")


def tool_discord_token_analyzer():
    """Analyze a single Discord token or paste; decode safe parts & redact secrets (Offline)."""
    s = Prompt.ask("Discord token or paste blob") if console else input("Token/text: ")
    text = s.strip()

    found = []
    for rx in DISCORD_TOKEN_PATTERNS:
        for m in rx.finditer(text):
            found.append(("user_token", m.group(1)))
    for m in DISCORD_BOT_TOKEN_RE.finditer(text):
        found.append(("bot_token", m.group(1)))

    if not found:
        cprint("[yellow]No token-looking strings found.[/]")
        return

    table = Table(title="Discord Token Analyzer (offline)", box=box.SIMPLE)
    table.add_column("Type")
    table.add_column("Preview", overflow="fold")
    table.add_column("Details", overflow="fold")

    payload = []
    for ttype, tok in found[:20]:
        details = {}
        preview = _redact_secret(tok)
        if ttype == "user_token":
            if tok.startswith("mfa."):
                details["kind"] = "mfa"
                details["segments"] = 1
            else:
                parts = tok.split(".")
                details["segments"] = len(parts)
                if len(parts) >= 1:
                    p1 = parts[0]
                    dec1 = _b64url_try(p1)
                    if dec1.isdigit():
                        details["user_id"] = dec1
                        # If it looks like a snowflake, decode timestamp/etc.
                        try:
                            snow = int(dec1)
                            info = _analyze_snowflake(snow)
                            details["user.utc_time"] = info.get("utc_time")
                        except Exception:
                            pass
                    elif dec1:
                        details["p1_decoded"] = dec1[:40] + ("…" if len(dec1) > 40 else "")
                if len(parts) >= 2:
                    dec2 = _b64url_try(parts[1])
                    if dec2:
                        details["p2_decoded_hint"] = dec2[:40] + ("…" if len(dec2) > 40 else "")
        else:  # bot token
            try:
                uid_b64, secret = tok.split(":", 1)
                uid = _b64url_try(uid_b64) or base64.b64decode(uid_b64 + "===").decode("utf-8", "ignore")
            except Exception:
                uid = ""
                secret = tok.split(":")[-1]
            details["bot.user_id_guess"] = uid if uid else "?"
            details["secret_preview"] = _redact_secret(secret)
            if uid and uid.isdigit():
                try:
                    info = _analyze_snowflake(int(uid))
                    details["bot.utc_time"] = info.get("utc_time")
                except Exception:
                    pass

        table.add_row(ttype, preview, json.dumps(details, indent=2))
        payload.append({"type": ttype, "token_preview": preview, "details": details})

    cprint(table)
    cprint("[dim]Note: No API calls are made. Output is for educational, defensive auditing only.[/]")
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("discord-token-analyze", payload)
        cprint(f"[green]Saved[/] {p}")


def tool_discord_token_leak_scan():
    """Scan a directory for Discord-like tokens (user/MFA/bot). Results redacted. Offline only."""
    root = Path(Prompt.ask("Path to scan", default=str(Path.cwd()))) if console else Path(input("Path: ") or str(Path.cwd()))
    exts = set(x.strip().lower() for x in (Prompt.ask("Extensions (comma, blank=all)", default="py,js,ts,env,json,txt,log,html,md") if console else input("Exts: ") or "py,js,ts,env,json,txt,log,html,md").split(",") if x.strip())
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and (not exts or p.suffix.lower().lstrip(".") in exts)]

    hits = []
    for f in files[:6000]:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rx in DISCORD_TOKEN_PATTERNS:
            for m in rx.finditer(text):
                hits.append({"file": str(f), "type": "user_token", "preview": _redact_secret(m.group(1))})
        for m in DISCORD_BOT_TOKEN_RE.finditer(text):
            hits.append({"file": str(f), "type": "bot_token", "preview": _redact_secret(m.group(1))})

    table = Table(title=f"Discord Token Leak Scan ({len(hits)} hits)", box=box.SIMPLE)
    table.add_column("File", overflow="fold")
    table.add_column("Type")
    table.add_column("Preview", overflow="fold")
    for h in hits[:250]:
        table.add_row(h["file"], h["type"], h["preview"])
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("discord-token-leaks", hits)
        cprint(f"[green]Saved[/] {p}")


# --- Telegram bot token analyzer ---
TELEGRAM_BOT_TOKEN_RE = re.compile(r"(?<!\d)(\d{5,20}:[A-Za-z0-9_-]{30,100})(?![A-Za-z0-9_-])")

def tool_telegram_bot_token_analyzer():
    """Analyze Telegram Bot API tokens (format: <bot_id>:<secret>) — redacts secret."""
    s = Prompt.ask("Telegram bot token or paste") if console else input("Token/text: ")
    text = s.strip()
    found = TELEGRAM_BOT_TOKEN_RE.findall(text)
    if not found:
        cprint("[yellow]No Telegram bot token-looking strings found.[/]")
        return
    table = Table(title="Telegram Bot Token Analyzer (offline)", box=box.SIMPLE)
    table.add_column("Preview")
    table.add_column("Bot ID")
    table.add_column("Notes", overflow="fold")
    payload = []
    for tok in found[:30]:
        bot_id = tok.split(":", 1)[0]
        prev = _redact_secret(tok)
        notes = "numeric id looks valid" if bot_id.isdigit() else "id not numeric?"
        table.add_row(prev, bot_id, notes)
        payload.append({"preview": prev, "bot_id": bot_id, "notes": notes})
    cprint(table)
    if Confirm.ask("Save JSON?", default=False):
        p = save_json_report("telegram-bot-token-analyze", payload)
        cprint(f"[green]Saved[/] {p}")


# --- Telegram deep link builder (for testing safe flows) ---
# Examples: username + start payload; joinchat code; proxies

def tool_telegram_deeplink_builder():
    """Build common t.me deep links (username start/startapp; joinchat; proxy)."""
    mode = Prompt.ask("Mode", choices=["start","startapp","joinchat","proxy"], default="start") if console else (input("Mode [start/startapp/joinchat/proxy]: ") or "start")
    if mode in {"start","startapp"}:
        username = Prompt.ask("Username (without @)") if console else input("Username: ")
        param = Prompt.ask("Payload (a-zA-Z0-9_)", default="payload") if console else (input("Payload: ") or "payload")
        url = f"https://t.me/{username}?{mode}={urlparse.quote_plus(param)}"
    elif mode == "joinchat":
        code = Prompt.ask("Invite code (e.g. AbCdEfGhIj)") if console else input("Code: ")
        url = f"https://t.me/joinchat/{code}"
    else:  # proxy
        host = Prompt.ask("Proxy host") if console else input("Host: ")
        port = Prompt.ask("Port", default="1080") if console else (input("Port: ") or "1080")
        url = f"https://t.me/socks?server={urlparse.quote_plus(host)}&port={urlparse.quote_plus(str(port))}"
    cprint(Panel.fit(url, title="t.me deep link", box=box.ROUNDED))


# --- QR decode (requires pyzbar + pillow) ---

try:
    import pyzbar
    from pyzbar.pyzbar import decode as _qr_decode
    from pyzbar import pyzbar as _pyzbar
    from PIL import Image
    print("✅ pyzbar + Pillow available")
    print("pyzbar version:", getattr(pyzbar, "__version__", "?"))
except Exception as e:
    print("❌ Import failed:", e)
    _qr_decode = None

def tool_qr_decode():
    """Decode QR/Barcodes from an image (requires pyzbar & pillow)."""
    if _qr_decode is None or Image is None:
        cprint("[yellow]pyzbar & pillow required:[/] pip install pyzbar Pillow")
        return
    path = Prompt.ask("Image file path") if console else input("Image: ")
    p = Path(path)
    if not p.exists():
        cprint("[red]File not found[/]")
        return
    try:
        img = Image.open(p)
        results = _qr_decode(img)
    except Exception as e:
        cprint(f"[red]Decode failed:[/] {e}")
        return
    if not results:
        cprint("[yellow]No codes detected.[/]")
        return
    table = Table(title=f"QR/Barcode Decode — {p.name}", box=box.SIMPLE)
    table.add_column("Type")
    table.add_column("Data", overflow="fold")
    for r in results:
        table.add_row(getattr(r, 'type', 'QR'), r.data.decode('utf-8', 'ignore'))
    cprint(table)


# --- URL Unshortener (follow redirects safely) ---
def tool_url_unshorten():
    """Follow HTTP redirects for a URL and show the hop chain (requires requests)."""
    if requests is None:
        cprint("[yellow]requests required:[/] pip install requests")
        return
    url = Prompt.ask("URL") if console else input("URL: ")
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
    except Exception as e:
        cprint(f"[red]Request failed:[/] {e}")
        return
    hops = [url]
    hops += [h.url for h in r.history]
    if not r.history or (hops and hops[-1] != r.url):
        hops.append(r.url)
    table = Table(title="Redirect Chain", box=box.MINIMAL)
    table.add_column("#", justify="right")
    table.add_column("URL", overflow="fold")
    table.add_column("Status")
    for i, resp in enumerate(r.history + [r], start=0):
        table.add_row(str(i), resp.url, str(resp.status_code))
    cprint(table)


# --- Register new tools (48–55) ---
TOOLS.extend([
    Tool("48", "Discord Token Analyzer", "Parse/redact Discord user/MFA/bot tokens (offline)", tool_discord_token_analyzer),
    Tool("49", "Discord Token Leak Scan", "Scan files for Discord-like tokens (redacted)", tool_discord_token_leak_scan),
    Tool("50", "Telegram Bot Token Analyzer", "Parse/redact Telegram bot tokens (offline)", tool_telegram_bot_token_analyzer),
    Tool("51", "Telegram Deep Link Builder", "Make t.me start/startapp/joinchat/proxy links", tool_telegram_deeplink_builder),
    Tool("52", "QR Decode", "Decode QR/barcodes from images (pyzbar)", tool_qr_decode),
    Tool("53", "URL Unshorten", "Follow redirects & list hop chain", tool_url_unshorten),
])


"""
Hacker-Life Lab — Image Metadata Add‑ons (Tools 56–58)
Drop-in module to extend your existing `main.py` with richer image tooling.

No hard dependencies: everything is optional & gracefully degrades.
- Pillow (PIL) strongly recommended: `pip install Pillow`
- piexif (optional for perfect JPEG EXIF strip): `pip install piexif`
- imagehash (optional for perceptual hashing): `pip install imagehash`

How to use:
1) Place this file next to your main.py, OR paste the contents near the bottom of your main file
   (before the Typer CLI build section) so the new tools can register themselves.
2) Ensure the following globals exist (they do in your main):
   cprint, Panel, Table, Prompt, Confirm, box, REPORTS_DIR, save_json_report, TOOLS
3) Run `python3 main.py` and look for tools #56–58 in the menu.
"""


def _exif_to_human(exif_raw: dict, ExifTags) -> Tuple[Dict, Dict]:
    """Split EXIF into metadata + GPS (humanized keys)."""
    gps_block: Dict[str, object] = {}
    meta: Dict[str, object] = {}
    try:
        tagmap = ExifTags.TAGS  # id -> name
        gpmap = ExifTags.GPSTAGS
    except Exception:
        tagmap = {}
        gpmap = {}
    for tid, val in (exif_raw or {}).items():
        name = tagmap.get(tid, str(tid))
        if name == "GPSInfo" and isinstance(val, dict):
            for k, v in val.items():
                gps_block[gpmap.get(k, str(k))] = v
        else:
            meta[name] = val
    return meta, gps_block


def _dms_to_decimal(dms, ref: str | None) -> float | None:
    try:
        deg = dms[0][0] / dms[0][1]
        minu = dms[1][0] / dms[1][1]
        sec = dms[2][0] / dms[2][1]
        dec = deg + (minu / 60.0) + (sec / 3600.0)
        if ref in ("S", "W"):
            dec = -dec
        return dec
    except Exception:
        return None


def _gps_to_decimal_pair(gps: Dict) -> Tuple[float | None, float | None]:
    lat = lon = None
    if gps:
        lat = _dms_to_decimal(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
        lon = _dms_to_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
    return lat, lon


def _image_basic_info(p: Path, Image):
    try:
        with Image.open(p) as im:
            info = {
                "path": str(p),
                "format": im.format,
                "mode": im.mode,
                "size": f"{im.width}x{im.height}",
                "width": im.width,
                "height": im.height,
            }
            try:
                info["icc_profile"] = bool(im.info.get("icc_profile"))
            except Exception:
                pass
            return info
    except Exception as e:
        return {"path": str(p), "error": str(e)}


def tool_image_metadata_pro():
    """Richer EXIF/metadata viewer: camera/lens, dates, orientation, GPS (decimal), and file basics.
    Supports multiple files or a directory (recurses images); optional JSON save.
    """
    Image, ExifTags = _safe_import_pillow()
    if Image is None:
        cprint("[yellow]Pillow required:[/] pip install Pillow")
        return
    target = Prompt.ask("Image path(s) or directory (comma)", default=str(Path.cwd())) if Prompt else input("Path(s): ")
    inputs = [Path(x.strip().strip('\\')) for x in target.split(",") if x.strip()]

    # Expand to image files
    EXTS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".bmp", ".gif", ".heic"}
    files: List[Path] = []
    for item in inputs:
        if item.is_file():
            files.append(item)
        elif item.is_dir():
            files.extend([p for p in item.rglob("*") if p.suffix.lower() in EXTS and p.is_file()])
    files = files[:1000]  # safety cap
    if not files:
        cprint("[red]No image files found.[/]")
        return

    rows = []
    payload = []
    for f in files:
        basic = _image_basic_info(f, Image)
        # Extract EXIF (if any)
        exif_meta = {}
        gps_meta = {}
        try:
            with Image.open(f) as im:
                raw = getattr(im, "_getexif", lambda: None)() or {}
                if raw:
                    exif_meta, gps_meta = _exif_to_human(raw, ExifTags)
        except Exception:
            pass

        # Friendly fields to highlight in the table
        camera = exif_meta.get("Model") or exif_meta.get("CameraModelName")
        maker = exif_meta.get("Make")
        lens = exif_meta.get("LensModel") or exif_meta.get("LensMake")
        dt = exif_meta.get("DateTimeOriginal") or exif_meta.get("DateTime") or exif_meta.get("CreateDate")
        orient = exif_meta.get("Orientation")
        lat, lon = _gps_to_decimal_pair(gps_meta)

        rows.append((
            f.name,
            basic.get("format", ""),
            f"{basic.get('width','?')}x{basic.get('height','?')}",
            (maker or "") + (" "+camera if camera else ""),
            lens or "",
            dt or "",
            f"{lat:.6f}" if isinstance(lat, float) else "-",
            f"{lon:.6f}" if isinstance(lon, float) else "-",
        ))
        payload.append({
            "file": str(f),
            "basic": basic,
            "exif": exif_meta,
            "gps": gps_meta,
            "gps_decimal": {"lat": lat, "lon": lon},
        })

    # Render summary table
    table = Table(title="Image Metadata Pro", box=box.MINIMAL_DOUBLE_HEAD if box else None)
    table.add_column("File", overflow="fold")
    table.add_column("Fmt")
    table.add_column("WxH")
    table.add_column("Camera")
    table.add_column("Lens", overflow="fold")
    table.add_column("Taken")
    table.add_column("Lat")
    table.add_column("Lon")
    for r in rows[:300]:
        table.add_row(*[str(x) for x in r])
    cprint(table)

    # Optional per-file detailed dump
    if Confirm and Confirm.ask("Show detailed EXIF per file?", default=False):
        for item in payload[:30]:
            body = json.dumps({
                "basic": item["basic"],
                "exif": item["exif"],
                "gps": item["gps"],
                "gps_decimal": item["gps_decimal"],
            }, indent=2, default=str)
            cprint(Panel.fit(body, title=item["file"], border_style="cyan"))

    if Confirm and Confirm.ask("Save JSON report?", default=True):
        out = save_json_report("image-meta-pro", payload)
        cprint(f"[green]Saved[/] {out}")


def tool_exif_scrub_rewrite():
    """EXIF/metadata scrubber: writes clean copies (no EXIF, no ICC unless kept), preserving pixels.
    JPEG: use piexif if available for a perfect strip; PNG/WebP: drop info chunks via Pillow re-save.
    """
    Image, _ = _safe_import_pillow()
    if Image is None:
        cprint("[yellow]Pillow required:[/] pip install Pillow")
        return
    try:
        import piexif  # type: ignore
    except Exception:
        piexif = None  # type: ignore

    src = Prompt.ask("Image path(s), comma") if Prompt else input("Path(s): ")
    keep_icc = Confirm.ask("Keep ICC profile (color accuracy)?", default=True) if Confirm else True
    targets = [Path(s.strip().strip('\\')) for s in src.split(",") if s.strip()]

    table = Table(title="EXIF Scrub Results", box=box.MINIMAL if box else None)
    table.add_column("Input", overflow="fold")
    table.add_column("Output", overflow="fold")
    table.add_column("Notes", overflow="fold")

    for p in targets:
        if not p.exists() or not p.is_file():
            table.add_row(str(p), "-", "not found")
            continue
        out = p.with_suffix(p.suffix.replace(".", ".cleaned."))
        note = ""
        try:
            with Image.open(p) as im:
                params = {}
                if keep_icc and "icc_profile" in im.info:
                    params["icc_profile"] = im.info.get("icc_profile")
                if p.suffix.lower() in {".jpg", ".jpeg"} and piexif is not None:
                    # Re-encode with empty EXIF
                    exif_bytes = piexif.dump({})
                    im.save(out, format="JPEG", exif=exif_bytes, **params)
                    note = "piexif strip"
                else:
                    # Pillow re-save without metadata
                    data = im.tobytes()
                    clean = Image.frombytes(im.mode, im.size, data)
                    fmt = im.format or p.suffix.lstrip(".").upper()
                    if fmt.upper() == "JPEG":
                        clean.save(out, format="JPEG", quality=95, optimize=True, **params)
                    else:
                        clean.save(out, format=fmt, **params)
                        note = "pillow re-save"
            table.add_row(str(p), str(out), note or "cleaned")
        except Exception as e:
            table.add_row(str(p), "-", f"ERR: {e}")
    cprint(table)


def _avg_hash_64(im) -> int:
    """Simple 8x8 average hash → 64-bit int (fallback if imagehash not installed)."""
    try:
        im = im.convert("L").resize((8, 8))
        pixels = list(im.getdata())
        avg = sum(pixels) / 64.0
        bits = 0
        for i, px in enumerate(pixels):
            if px >= avg:
                bits |= (1 << i)
        return bits
    except Exception:
        return 0


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def tool_image_dupe_finder():
    """Perceptual duplicate finder: walks a directory, computes pHash/dHash (if available) or avgHash,
    and groups near-duplicates by Hamming distance threshold (default 5).
    """
    Image, _ = _safe_import_pillow()
    if Image is None:
        cprint("[yellow]Pillow required:[/] pip install Pillow")
        return
    try:
        import imagehash  # type: ignore
        imagehash_available = True
    except Exception:
        imagehash = None  # type: ignore
        imagehash_available = False

    root = Path(Prompt.ask("Directory", default=str(Path.cwd())) if Prompt else input("Directory: ") or str(Path.cwd()))
    try:
        threshold = int(Prompt.ask("Hamming threshold (0–10)", default="5") if Prompt else (input("Threshold [5]: ") or 5))
    except Exception:
        threshold = 5

    EXTS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".tif", ".tiff"}
    files = [p for p in root.rglob("*") if p.suffix.lower() in EXTS and p.is_file()][:5000]
    if not files:
        cprint("[red]No images found in directory.[/]")
        return

    # Compute hashes
    # If imagehash is available, store ImageHash objects (NOT .hash numpy arrays)
    # Else store our 64-bit int avg-hash
    recs: list[tuple[Path, object]] = []
    for p in files:
        try:
            with Image.open(p) as im:
                if imagehash_available:
                    h = imagehash.phash(im)  # ImageHash object
                    recs.append((p, h))
                else:
                    recs.append((p, _avg_hash_64(im)))  # int
        except Exception:
            continue

    # Group near-duplicates
    groups: List[List[Path]] = []
    used = set()
    for i in range(len(recs)):
        if i in used:
            continue
        base_p, base_h = recs[i]
        group = [base_p]
        used.add(i)
        for j in range(i + 1, len(recs)):
            if j in used:
                continue
            pj, hj = recs[j]
            # Hamming distance
            if imagehash_available:
                # ImageHash supports subtraction -> Hamming distance (int)
                dist = int(base_h - hj)  # type: ignore[operator]
            else:
                dist = _hamming(int(base_h), int(hj))  # both are ints
            if dist <= threshold:
                group.append(pj)
                used.add(j)
        if len(group) > 1:
            groups.append(group)

    title = f"Image Duplicate Finder — {len(groups)} groups"
    table = Table(title=title, box=box.MINIMAL if box else None)
    table.add_column("Group #", justify="right")
    table.add_column("Members", overflow="fold")
    for idx, grp in enumerate(groups, start=1):
        table.add_row(str(idx), "\n".join(str(x) for x in grp[:10]))
    cprint(table)

    if Confirm and Confirm.ask("Save JSON groups?", default=True):
        payload = [[str(x) for x in grp] for grp in groups]
        out = save_json_report("image-dup-groups", payload)
        cprint(f"[green]Saved[/] {out}")


# === Register in the global TOOLS list (IDs 56–58) ===
try:
    TOOLS  # type: ignore[name-defined]
    Tool   # type: ignore[name-defined]
except Exception:
    # We are imported standalone (e.g., for static analysis). Define soft shims.
    class Tool:
        def __init__(self, key: str, name: str, desc: str, fn):
            self.key, self.name, self.desc, self.fn = key, name, desc, fn
    TOOLS = []  # type: ignore

# Finally, extend the menu
TOOLS.extend([
    Tool("54", "Image Metadata Pro", "Camera/lens/dates + GPS decimal; JSON export", tool_image_metadata_pro),
    Tool("55", "EXIF Scrub (rewrite)", "Write clean copies with metadata removed", tool_exif_scrub_rewrite),
    Tool("56", "Image Duplicate Finder", "Perceptual hash (pHash/avgHash) near-dup groups", tool_image_dupe_finder),
])


# ---------- Typer CLI (optional) ----------

def build_cli():
    app = typer.Typer(help=f"{APP_NAME} — Interactive menu + CLI utilities")

    @app.command()
    def menu():
        """Launch the interactive Rich menu (default if no args)."""
        interactive_menu()

    @app.command()
    def scan(
        host: str,
        ports: str = typer.Option("top1k", help="Port list (e.g. 1-1024,80,443 or 'top1k')"),
        timeout: float = typer.Option(1.0, help="Timeout per port in seconds"),
        out: Optional[str] = typer.Option(None, help="Write results to JSON file")
    ):
        """Run the async port scanner quickly from CLI."""
        try:
            ip = socket.gethostbyname(host)
        except Exception as e:
            typer.echo(f"DNS failed: {e}")
            raise typer.Exit(1)

        if ports == "top1k":
            port_list = sorted(set(list(COMMON_PORTS.keys()) + list(range(1, 1025))))
        else:
            port_list = []
            for seg in ports.split(","):
                seg = seg.strip()
                if not seg:
                    continue
                if "-" in seg:
                    a, b = seg.split("-", 1)
                    port_list += list(range(int(a), int(b) + 1))
                else:
                    port_list.append(int(seg))
            port_list = sorted(set(port_list))

        results = asyncio.run(_scan_host(ip, port_list, timeout=timeout))
        typer.echo(json.dumps(results, indent=2))
        if out:
            Path(out).write_text(json.dumps(results, indent=2))

    @app.command()
    def phone(number: str, region: str = typer.Option("US", help="Default region if no +country")):
        """CLI phone intel (requires phonenumbers)."""
        if phonenumbers is None:
            typer.echo("Install phonenumbers first: pip install phonenumbers")
            raise typer.Exit(1)
        try:
            pn = phonenumbers.parse(number, region)
            data = {
                "input": number,
                "e164": phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164) if phonenumbers.is_valid_number(pn) else "",
                "valid": phonenumbers.is_valid_number(pn),
                "type": str(phonenumbers.number_type(pn)),
                "region": phone_geocoder.description_for_number(pn, "en") if phone_geocoder else "",
                "carrier": phone_carrier.name_for_number(pn, "en") if phone_carrier else "",
                "timezones": list(phone_timezone.time_zones_for_number(pn)) if phone_timezone else [],
            }
            typer.echo(json.dumps(data, indent=2))
        except Exception as e:
            typer.echo(json.dumps({"input": number, "error": str(e)}, indent=2))
            raise typer.Exit(1)

    return app


def main():
    if typer is not None:
        app = build_cli()
        # If no arguments given → default to menu
        if len(sys.argv) == 1:
            interactive_menu()
        else:
            app()
    else:
        interactive_menu()


if __name__ == "__main__":
    main()

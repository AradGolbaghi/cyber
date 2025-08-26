#!/usr/bin/env python3
"""
owner_setup.py — Cross-platform "owner + setup" script
- Shows ASCII art and opens your links
- Installs system deps across Windows/macOS/Linux (best-effort)
- Installs Python deps (switches to python-magic-bin on Windows)
- Verifies imports

Flags:
  --no-open     Skip opening web links
  --no-sys      Skip system package installs
  --no-py       Skip Python package installs
  --no-verify   Skip import verification
"""

from __future__ import annotations
import sys, os, platform, subprocess, argparse, shutil, webbrowser as wb

# -------- OWNER: ASCII + links ----------
LINKS = [
    "https://github.com/AradGolbaghi",
    "https://guns.lol/aradgol",
    "https://lichess.org/@/AradEE",
    "https://discord.com/invite/VeNPNnwTYP",
    "https://arad-seven.vercel.app/",
    "https://www.snapchat.com/@alright.cc",
    "https://discord.com/users/1328403854357696513",
]

def show_ascii():
    try:
        from colorama import Fore, Style, init as colorama_init
        import pyfiglet
        colorama_init(autoreset=True)
        ascii_art = pyfiglet.figlet_format("ARAD GOL", font="slant")
        palette = [getattr(Fore, name) for name in
                   ["RED","GREEN","YELLOW","BLUE","MAGENTA","CYAN","LIGHTBLACK_EX"]]
        for i, line in enumerate(ascii_art.splitlines()):
            print(palette[i % len(palette)] + line)
    except Exception:
        print("=== ARAD GOL ===")

def open_links():
    for i, link in enumerate(LINKS, 1):
        try:
            print(f"Opening {i}: {link}")
            wb.open_new_tab(link)
        except Exception as e:
            print(f"Failed to open {link}: {e}")

# --------- SETUP: system + python deps ----------
INFO, OK, ERR, RUN = "ℹ️", "✅", "❌", "🚀"

# Python deps you asked for (switch python-magic → python-magic-bin on Windows)
BASE_REQUIREMENTS = [
    # ASCII / Terminal
    "pyfiglet",
    "colorama",
    "termcolor",
    # CLI / UI
    "rich",
    "typer",
    # Networking
    "requests",
    "dnspython",
    "scapy",
    "python-whois",
    # Phone number utilities
    "phonenumbers",
    # Imaging / QR / EXIF / Hash
    "Pillow",
    "qrcode[pil]",
    "pyzbar",
    "piexif",
    "imagehash",
    # PDF parsing
    "pypdf",
    "pdfminer.six",
    # Password strength estimation
    "zxcvbn",
    # Hashing
    "mmh3",
    # magic lib (platform-specific selection below)
    # "python-magic" or "python-magic-bin"
    # Optional utilities
    "whois",
]

# Import checks to validate installation
CHECK_IMPORTS = [
    ("pyfiglet", "ASCII"),
    ("colorama", "Terminal Colors"),
    ("termcolor", "Terminal Colors"),
    ("rich", "UI"),
    ("typer", "CLI"),
    ("requests", "HTTP"),
    ("dns", "DNS"),
    ("scapy.all", "Packets"),
    ("whois", "WHOIS (python-whois)"),
    ("phonenumbers", "Phone"),
    ("PIL", "Imaging (Pillow)"),
    ("qrcode", "QR"),
    ("pyzbar", "QR Decode"),
    ("piexif", "EXIF"),
    ("imagehash", "Image Hash"),
    ("pypdf", "PDF"),
    ("pdfminer", "PDF Miner"),
    ("zxcvbn", "Password Strength"),
    ("mmh3", "MurmurHash"),
    ("magic", "File Magic"),
]

def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    print(f"{RUN} $ {' '.join(cmd)}")
    return subprocess.run(cmd, check=check)

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def detect_linux_pm() -> tuple[str|None, list[str]]:
    """Return (pm, install_cmd_prefix) for Linux distros if found."""
    if have("apt"):
        return "apt", ["sudo", "apt", "install", "-y"]
    if have("dnf"):
        return "dnf", ["sudo", "dnf", "install", "-y"]
    if have("yum"):
        return "yum", ["sudo", "yum", "install", "-y"]
    if have("pacman"):
        return "pacman", ["sudo", "pacman", "-S", "--noconfirm"]
    if have("zypper"):
        return "zypper", ["sudo", "zypper", "--non-interactive", "install", "-y"]
    return None, []

def linux_packages_by_pm(pm: str) -> list[str]:
    """Map desired packages to the distro's repo names."""
    # Common tools
    base_tools = ["curl", "jq", "nmap", "whois"]
    if pm in ("apt", "dnf", "yum"):
        extra = {
            "apt":    ["tshark", "tcpdump", "libpcap-dev", "libzbar0", "zbar-tools", "libmagic1", "net-tools"],
            "dnf":    ["wireshark-cli", "tcpdump", "libpcap-devel", "zbar", "file-libs", "net-tools"],
            "yum":    ["wireshark-cli", "tcpdump", "libpcap-devel", "zbar", "file-libs", "net-tools"],
        }[pm]
        return extra + base_tools
    if pm == "pacman":
        return ["wireshark-cli", "tcpdump", "zbar", "file", "net-tools"] + base_tools
    if pm == "zypper":
        return ["wireshark-cli", "tcpdump", "libpcap-devel", "zbar", "file", "net-tools"] + base_tools
    return base_tools

def install_system_deps(skip: bool) -> None:
    if skip:
        print(f"{INFO} Skipping system package installs (--no-sys).")
        return

    osname = platform.system()
    if osname == "Darwin":
        print(f"{INFO} Detected macOS.")
        if have("brew"):
            pkgs = ["wireshark", "tcpdump", "zbar", "libmagic", "nmap", "curl", "jq", "whois"]
            try:
                run(["brew", "update"], check=False)
                run(["brew", "install"] + pkgs)
                print(f"{OK} Homebrew packages installed.")
            except Exception as e:
                print(f"{ERR} brew install failed: {e}")
        else:
            print(f"{ERR} Homebrew not found. Install from https://brew.sh then re-run, or use --no-sys.")
        return

    if osname == "Windows":
        print(f"{INFO} Detected Windows.")
        # Prefer Chocolatey; fallback to winget
        installed = False
        if have("choco"):
            # zbar on Windows via choco: try 'zbar' or 'zbar.light' if available
            pkgs = ["wireshark", "nmap", "curl", "jq", "whois"]
            try:
                run(["choco", "install", "-y"] + pkgs, check=False)
                installed = True
            except Exception as e:
                print(f"{ERR} choco install failed: {e}")
            # Try zbar separately if package exists
            for cand in ("zbar", "zbar.light"):
                if not installed and have("choco"):
                    try:
                        run(["choco", "install", "-y", cand], check=False)
                    except Exception:
                        pass
        if not installed and have("winget"):
            # winget ids may vary; we install the big ones
            try:
                run(["winget", "install", "--silent", "--accept-package-agreements",
                     "--accept-source-agreements", "WiresharkFoundation.Wireshark"], check=False)
                run(["winget", "install", "--silent", "--accept-package-agreements",
                     "--accept-source-agreements", "Insecure.Nmap"], check=False)
                run(["winget", "install", "--silent", "--accept-package-agreements",
                     "--accept-source-agreements", "GnuWin32.Curl"], check=False)
                run(["winget", "install", "--silent", "--accept-package-agreements",
                     "--accept-source-agreements", "stedolan.jq"], check=False)
                # whois: NirSoft whois or Microsoft Sysinternals whois (pick one if present)
                run(["winget", "install", "--silent", "--accept-package-agreements",
                     "--accept-source-agreements", "Sysinternals.WhoIs"], check=False)
                installed = True
            except Exception as e:
                print(f"{ERR} winget install failed: {e}")
        if not installed:
            print(f"{INFO} Could not auto-install system deps. You can continue; Python deps may still work.")
        print(f"{INFO} Note: On Windows, pyzbar needs ZBar DLL. Installing Wireshark does not provide it.")
        print(f"{INFO} You can try `choco install zbar` or download ZBar binaries and add zbar DLL to PATH.")
        return

    if osname == "Linux":
        print(f"{INFO} Detected Linux.")
        pm, install_prefix = detect_linux_pm()
        if not pm:
            print(f"{ERR} No supported package manager found. Install system deps manually or use --no-sys.")
            return
        try:
            if pm in ("apt", "dnf", "yum"):
                # update cache first
                run(["sudo", pm, "update", "-y"] if pm != "apt" else ["sudo", "apt", "update"])
            pkgs = linux_packages_by_pm(pm)
            run(install_prefix + pkgs, check=False)
            print(f"{OK} System deps installed via {pm}.")
        except Exception as e:
            print(f"{ERR} {pm} install failed: {e}")
        return

    print(f"{INFO} Unknown OS '{osname}'. Skipping system deps.")

def python_requirements_for_platform() -> list[str]:
    reqs = BASE_REQUIREMENTS.copy()
    if platform.system() == "Windows":
        # python-magic on Windows usually needs the binary wheel
        reqs.append("python-magic-bin")
    else:
        reqs.append("python-magic")
    return reqs

def install_python_deps(skip: bool) -> None:
    if skip:
        print(f"{INFO} Skipping Python package installs (--no-py).")
        return
    py = sys.executable
    reqs = python_requirements_for_platform()
    print(f"{INFO} Installing Python requirements…")
    try:
        run([py, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"], check=False)
        run([py, "-m", "pip", "install"] + reqs, check=False)
        print(f"{OK} Python deps installed (best-effort).")
    except Exception as e:
        print(f"{ERR} pip install failed: {e}")

def verify_imports(skip: bool) -> None:
    if skip:
        print(f"{INFO} Skipping import verification (--no-verify).")
        return
    print(f"{INFO} Verifying critical imports…")
    for mod, desc in CHECK_IMPORTS:
        try:
            __import__(mod.split('.')[0])
            print(f"{OK} {desc} → {mod}")
        except Exception as e:
            print(f"{ERR} Import failed for {mod}: {e}")

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Owner + Setup (cross-platform)")
    p.add_argument("--no-open", action="store_true", help="Do not open web links")
    p.add_argument("--no-sys", action="store_true", help="Skip system package installs")
    p.add_argument("--no-py", action="store_true", help="Skip Python package installs")
    p.add_argument("--no-verify", action="store_true", help="Skip import verification")
    return p.parse_args()

def main():
    print(f"{INFO} Python {sys.version.split()[0]} on {platform.system()} ({platform.machine()})")
    if sys.version_info < (3, 8):
        print(f"{ERR} Python 3.8+ recommended (3.10+ ideal).")
    args = parse_args()

    # Owner bits
    show_ascii()
    if not args.no_open:
        open_links()

    # Setup bits
    install_system_deps(skip=args.no_sys)
    install_python_deps(skip=args.no_py)
    verify_imports(skip=args.no_verify)

    print(f"{INFO} Done.")
    print(f"{RUN} Tip: run your app with: python3 main.py")

if __name__ == "__main__":
    main()

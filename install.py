#!/usr/bin/env python3
"""
AuthProbe installer — checks Python version and installs dependencies.
"""
import subprocess
import sys

REQUIREMENTS = [
    "requests>=2.28.0",
    "requests-ntlm>=1.2.0",
    "requests-kerberos>=0.14.0",
    "pyotp>=2.8.0",
]

BANNER = """
╔═══════════════════════════════════════╗
║     AuthProbe — Installer             ║
╚═══════════════════════════════════════╝
"""


def main():
    print(BANNER)

    if sys.version_info < (3, 8):
        print(f"ERROR: Python 3.8+ required (you have {sys.version})")
        sys.exit(1)

    print(f"  Python: {sys.version.split()[0]}  ✓")
    print()

    for pkg in REQUIREMENTS:
        print(f"  Installing {pkg}…")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print(f"  ✓ {pkg}")
        except subprocess.CalledProcessError:
            pkg_name = pkg.split(">=")[0]
            print(f"  ! {pkg_name} — optional, some features may be unavailable")

    print()
    print("  Installation complete.")
    print()
    print("  Usage:")
    print("    python3 authprobe.py --url https://target.com --type webapp")
    print("    python3 authprobe.py --url https://api.target.com --type api")
    print("    python3 authprobe.py --url https://target.com --username admin --password secret")
    print("    python3 authprobe.py --url https://target.com --username admin --password secret --totp-secret BASE32SECRET")
    print()


if __name__ == "__main__":
    main()

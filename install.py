#!/usr/bin/env python3
"""
AuthProbe installer — checks Python version and installs dependencies.
"""
import subprocess
import sys


def _pip_installed(pkg_spec):
    """Return True if a pip package is already importable."""
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "requests-ntlm": "requests_ntlm", "requests-kerberos": "requests_kerberos",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    return importlib.util.find_spec(mod) is not None


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

    failed = []
    _to_install = []
    for pkg in REQUIREMENTS:
        if _pip_installed(pkg):
            print(f"  ✓ {pkg} already installed")
        else:
            _to_install.append(pkg)

    for pkg in _to_install:
        print(f"  Installing {pkg}…")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", pkg, "--quiet",
                 "--break-system-packages"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print(f"  ✓ {pkg}")
        except subprocess.CalledProcessError:
            print(f"  ✗ {pkg} — FAILED")
            failed.append(pkg)

    if not _to_install and not failed:
        print("  All pip packages already installed.")

    if failed:
        print()
        print(f"  ERROR: {len(failed)} package(s) failed to install:")
        for pkg in failed:
            print(f"    - {pkg}")
        print()
        print("  Fix the errors above and re-run install.py.")
        sys.exit(1)

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

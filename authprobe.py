#!/usr/bin/env python3
"""
authprobe.py — Authentication Detection & Probing Tool

Probes a target URL (web application or API) to detect authentication methods
in use and optionally validates credentials for each method.

Usage:
    python3 authprobe.py --url https://target.com [options]
    python3 authprobe.py --url https://api.target.com --type api [options]
"""

import argparse
import json
import re
import sys
import time
import warnings
from urllib.parse import urljoin, urlparse

VERSION = "1.0.0"

# Suppress SSL warnings for testing
warnings.filterwarnings("ignore")

BANNER = r"""
╔══════════════════════��═══════════════════════════���════════╗
║                                                           ║
║    █████╗ ██╗   ██╗████████╗██╗  ██╗                     ║
║   ██╔══██╗██║   ██║╚══██╔══╝██║  ██║                     ║
║   ███████║██║   ██║   ██║   ███████║                     ║
║   ██╔══██║██║   ██║   ██║   ██╔══██║                     ║
║   ██║  ██║╚██████╔╝   ██║   ██║  ██║                     ║
║   ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝                     ║
║                                                           ║
║   ██████╗ ██████╗  ██████╗ ██████╗ ███████╗              ║
║   ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝              ║
║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗                ║
║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝                ║
║   ██║     ██║  ██║╚██████╔╝██████╔╝███████╗              ║
║   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝              ║
║                                                           ║
║   Authentication Detection & Probing Tool  v{ver:<8}    ║
║   For authorized security testing only                    ║
╚═════════════════════════════════════════════════��═════════╝
""".format(ver=VERSION)

# ──────────────────────���───────────────────────────────��──────
# Colour helpers (fallback to plain if no ANSI support)
# ─────────────────────────────────────────────────────────────
def _c(code, text):
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

def red(t):    return _c("31", t)
def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def cyan(t):   return _c("36", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)


# ───────────────────────���────────────────────────────��────────
# Detection signatures
# ─────────────────────────────────────────────────────────────

# WWW-Authenticate header → method
_WWW_AUTH_MAP = {
    "basic":     "HTTP Basic",
    "digest":    "HTTP Digest",
    "bearer":    "Bearer Token",
    "ntlm":      "NTLM",
    "negotiate": "Kerberos/SPNEGO",
    "oauth":     "OAuth",
}

# Response body patterns that hint at form login
_FORM_LOGIN_PATTERNS = [
    re.compile(r'<input[^>]+type=["\']password["\']', re.I),
    re.compile(r'<form[^>]+action=["\'][^"\']*log[^"\']*["\']', re.I),
    re.compile(r'<form[^>]+action=["\'][^"\']*sign.?in[^"\']*["\']', re.I),
    re.compile(r'<form[^>]+action=["\'][^"\']*auth[^"\']*["\']', re.I),
    re.compile(r'id=["\']login', re.I),
    re.compile(r'id=["\']signin', re.I),
    re.compile(r'name=["\']password["\']', re.I),
]

# JSON response keys that indicate a token-based login API
_TOKEN_LOGIN_JSON_KEYS = {
    "access_token", "token", "jwt", "id_token", "auth_token",
    "bearer", "sessionToken",
}

# Cookie names that indicate session-based auth
_SESSION_COOKIE_NAMES = re.compile(
    r"(session|sess|auth|jwt|token|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|"
    r"connect\.sid|sid|sso|remember_me)",
    re.I,
)

# Header names that indicate API key auth
_API_KEY_HEADERS = re.compile(
    r"(X-API-Key|X-Auth-Token|X-Access-Token|Authorization|"
    r"X-App-Key|X-App-Token|API-Key|X-RapidAPI-Key)",
    re.I,
)

# Common login / auth endpoint paths
_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/auth/login",
    "/api/login", "/api/auth", "/api/auth/login", "/api/signin",
    "/api/token", "/oauth/token", "/connect/token",
    "/v1/auth", "/v1/login", "/v2/auth", "/v2/login",
    "/user/login", "/users/login", "/account/login",
    "/api/v1/auth", "/api/v1/login", "/api/v2/auth", "/api/v2/login",
]

# Well-known OAuth/OIDC metadata paths
_OAUTH_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]


# ─────────────────────────────────────────────────────────────
# Session factory
# ─────────────────────────────────────────────────────────────

def _make_session(args):
    try:
        import requests
        from requests.adapters import HTTPAdapter
    except ImportError:
        print(red("ERROR: requests library not installed. Run: pip install requests"))
        sys.exit(1)
    sess = requests.Session()
    sess.verify = False
    sess.headers.update({
        "User-Agent": f"AuthProbe/{VERSION} (Security Assessment)",
        "Accept": "text/html,application/json,*/*",
    })
    if args.proxy:
        sess.proxies = {"http": args.proxy, "https": args.proxy}
    adapter = HTTPAdapter(max_retries=1)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    return sess


# ─────────────────────────────────────────────────────────────
# Probe helpers
# ─────────────────────────────────────────────────────────────

def _safe_get(sess, url, timeout, **kwargs):
    try:
        return sess.get(url, timeout=timeout, allow_redirects=True, **kwargs)
    except Exception:
        return None


def _safe_post(sess, url, timeout, **kwargs):
    try:
        return sess.post(url, timeout=timeout, allow_redirects=True, **kwargs)
    except Exception:
        return None


def _parse_www_auth(header_value: str) -> list[str]:
    """Extract scheme names from a WWW-Authenticate header."""
    schemes = []
    for part in header_value.split(","):
        part = part.strip()
        scheme = part.split()[0].lower() if part else ""
        if scheme:
            schemes.append(scheme)
    return schemes


# ─────────────────────────────────────────────────────────────
# Detectors
# ─────────────────────────────────────────────────────────────

def detect_www_authenticate(resp, findings: dict):
    """Check WWW-Authenticate header on 401 responses."""
    if resp is None:
        return
    if resp.status_code not in (401, 403):
        return
    www_auth = resp.headers.get("WWW-Authenticate", "")
    if not www_auth:
        return
    for scheme in _parse_www_auth(www_auth):
        label = _WWW_AUTH_MAP.get(scheme, f"Unknown ({scheme})")
        findings["www_authenticate"].append({
            "scheme": scheme,
            "label":  label,
            "header": www_auth,
        })


def detect_form_login(resp, findings: dict):
    """Look for HTML login form patterns in the response body."""
    if resp is None or resp.status_code not in (200, 301, 302):
        return
    ct = resp.headers.get("Content-Type", "")
    if "html" not in ct.lower():
        return
    body = resp.text
    matches = [p.pattern for p in _FORM_LOGIN_PATTERNS if p.search(body)]
    if matches:
        findings["form_login"] = True
        findings["form_login_evidence"] = matches[:3]


def detect_api_token_login(resp, url: str, findings: dict):
    """
    Probe common API auth endpoints and look for token responses.
    Only used when --type api is set.
    """
    if resp is None:
        return
    ct = resp.headers.get("Content-Type", "")
    if "json" not in ct.lower():
        return
    try:
        data = resp.json()
    except Exception:
        return
    if isinstance(data, dict):
        keys = {k.lower() for k in data.keys()}
        if keys & {k.lower() for k in _TOKEN_LOGIN_JSON_KEYS}:
            findings["token_login_likely"] = True
            findings["token_login_url"] = url


def detect_session_cookies(resp, findings: dict):
    """Look for session/auth cookie names."""
    if resp is None:
        return
    for cookie in resp.cookies:
        if _SESSION_COOKIE_NAMES.search(cookie.name):
            findings["session_cookies"].append(cookie.name)


def detect_oauth_discovery(sess, base_url: str, timeout: int, findings: dict):
    """Probe /.well-known/ paths for OAuth/OIDC discovery."""
    for path in _OAUTH_DISCOVERY_PATHS:
        url = base_url.rstrip("/") + path
        r = _safe_get(sess, url, timeout)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if "issuer" in data or "token_endpoint" in data or "authorization_endpoint" in data:
                    findings["oauth_discovery"].append({
                        "path": path,
                        "issuer": data.get("issuer", ""),
                        "token_endpoint": data.get("token_endpoint", ""),
                        "authorization_endpoint": data.get("authorization_endpoint", ""),
                    })
            except Exception:
                pass


def detect_login_endpoints(sess, base_url: str, timeout: int, probe_type: str, findings: dict):
    """Probe common login endpoint paths."""
    found = []
    for path in _LOGIN_PATHS:
        if probe_type == "webapp" and path.startswith("/api/"):
            continue
        if probe_type == "api" and not path.startswith("/api") and "token" not in path:
            continue
        url = base_url.rstrip("/") + path
        r = _safe_get(sess, url, timeout)
        if r and r.status_code in (200, 301, 302, 401, 403):
            found.append({
                "path": path,
                "status": r.status_code,
                "content_type": r.headers.get("Content-Type", "")[:60],
            })
            # Check for JSON token endpoint
            detect_api_token_login(r, url, findings)
            # Check for form login
            if probe_type == "webapp":
                detect_form_login(r, findings)
    if found:
        findings["login_endpoints"] = found


def detect_security_headers(resp, findings: dict):
    """Check for auth-related security headers."""
    if resp is None:
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}
    security = {}
    if "x-frame-options" in headers:
        security["X-Frame-Options"] = headers["x-frame-options"]
    if "content-security-policy" in headers:
        security["Content-Security-Policy"] = headers["content-security-policy"][:80] + "…"
    if "strict-transport-security" in headers:
        security["Strict-Transport-Security"] = headers["strict-transport-security"]
    if "x-content-type-options" in headers:
        security["X-Content-Type-Options"] = headers["x-content-type-options"]
    if security:
        findings["security_headers"] = security

    # Check for API key header hints in response headers
    for h in resp.headers:
        if _API_KEY_HEADERS.search(h):
            findings["api_key_header_hints"].append(h)


def detect_ntlm_kerberos(resp, findings: dict):
    """Detect NTLM / Kerberos from WWW-Authenticate."""
    if resp is None:
        return
    www_auth = resp.headers.get("WWW-Authenticate", "").lower()
    if "ntlm" in www_auth:
        findings["ntlm_detected"] = True
    if "negotiate" in www_auth:
        findings["kerberos_detected"] = True


def detect_basic_auth(resp, findings: dict):
    if resp is None:
        return
    www_auth = resp.headers.get("WWW-Authenticate", "").lower()
    if www_auth.startswith("basic"):
        realm = ""
        m = re.search(r'realm=["\']([^"\']+)["\']', www_auth, re.I)
        if m:
            realm = m.group(1)
        findings["basic_auth"] = {"realm": realm}


# ─────────────────────────────────────────────────────────────
# Credential validation
# ─────────────────────────────────────────────────────────────

def validate_basic(sess, url: str, username: str, password: str, timeout: int) -> dict:
    r = _safe_get(sess, url, timeout, auth=(username, password))
    if r and r.status_code not in (401, 403):
        return {"method": "basic", "success": True, "status": r.status_code}
    return {"method": "basic", "success": False, "status": r.status_code if r else None}


def validate_bearer(sess, url: str, token: str, timeout: int) -> dict:
    import copy
    s2 = copy.copy(sess)
    s2.headers = dict(sess.headers)
    s2.headers["Authorization"] = f"Bearer {token}"
    r = _safe_get(s2, url, timeout)
    if r and r.status_code not in (401, 403):
        return {"method": "bearer", "success": True, "status": r.status_code}
    return {"method": "bearer", "success": False, "status": r.status_code if r else None}


def validate_form_login(sess, login_url: str, username: str, password: str, timeout: int) -> dict:
    # Try common field name combinations
    for ufield, pfield in [("username", "password"), ("email", "password"), ("user", "pass"), ("login", "password")]:
        r = _safe_post(sess, login_url, timeout, data={ufield: username, pfield: password})
        if r and r.status_code not in (401, 403) and r.url != login_url:
            return {"method": "form_login", "success": True, "status": r.status_code, "redirected_to": r.url}
        if r and r.status_code == 200:
            body = r.text.lower()
            if "logout" in body or "dashboard" in body or "welcome" in body or "sign out" in body:
                return {"method": "form_login", "success": True, "status": r.status_code, "evidence": "logout/welcome text found"}
    return {"method": "form_login", "success": False, "status": r.status_code if r else None}


# ─────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────

def _print_section(title):
    print(f"\n{bold(cyan('━' * 60))}")
    print(f"  {bold(title)}")
    print(f"{bold(cyan('━' * 60))}")


def _print_findings(findings: dict, args):
    detected = []

    if findings.get("basic_auth"):
        realm = findings["basic_auth"].get("realm", "")
        detected.append(("HTTP Basic Auth", f"realm={realm}" if realm else ""))

    if findings.get("ntlm_detected"):
        detected.append(("NTLM / Windows Auth", "Active Directory environment likely"))

    if findings.get("kerberos_detected"):
        detected.append(("Kerberos / SPNEGO", "SSO environment detected"))

    for entry in findings.get("www_authenticate", []):
        label = entry["label"]
        if label not in [d[0] for d in detected]:
            detected.append((label, f"WWW-Authenticate: {entry['header'][:60]}"))

    if findings.get("form_login"):
        evidence = findings.get("form_login_evidence", [])
        detected.append(("Form-based Login", f"{len(evidence)} HTML form pattern(s) matched"))

    if findings.get("token_login_likely"):
        url = findings.get("token_login_url", "")
        detected.append(("Token / JWT Login API", f"endpoint: {url}"))

    for entry in findings.get("oauth_discovery", []):
        detected.append(("OAuth2 / OIDC", f"issuer: {entry.get('issuer','?')} | token_ep: {entry.get('token_endpoint','?')}"))

    if findings.get("session_cookies"):
        names = ", ".join(findings["session_cookies"][:5])
        detected.append(("Session Cookie Auth", f"cookie names: {names}"))

    if findings.get("api_key_header_hints"):
        hints = ", ".join(findings["api_key_header_hints"][:3])
        detected.append(("API Key (header)", f"hint headers: {hints}"))

    _print_section("DETECTED AUTHENTICATION METHODS")
    if detected:
        for method, detail in detected:
            print(f"  {green('✓')}  {bold(method)}")
            if detail:
                print(f"       {dim(detail)}")
    else:
        print(f"  {yellow('?')}  No strong auth signals detected")
        print(f"       {dim('Target may be unauthenticated, or auth is on a sub-path')}")

    if findings.get("login_endpoints"):
        _print_section("LOGIN ENDPOINTS FOUND")
        for ep in findings["login_endpoints"]:
            status_colour = green if ep["status"] in (200, 302) else yellow
            print(f"  {status_colour(str(ep['status']))}  {ep['path']}  {dim(ep['content_type'])}")

    if findings.get("security_headers"):
        _print_section("SECURITY HEADERS")
        for k, v in findings["security_headers"].items():
            print(f"  {cyan(k)}: {dim(v)}")

    if findings.get("validation_results"):
        _print_section("CREDENTIAL VALIDATION")
        for r in findings["validation_results"]:
            ok = r.get("success", False)
            m  = r.get("method", "?")
            sc = r.get("status", "?")
            extra = r.get("redirected_to", r.get("evidence", ""))
            icon = green("✓ VALID") if ok else red("✗ FAILED")
            print(f"  {icon}  method={bold(m)}  status={sc}  {dim(extra)}")

    _print_section("RECOMMENDED AUTH METHOD FOR FRACTURE / SIPHON")
    if findings.get("ntlm_detected"):
        print(f"  → {bold('ntlm')}  (requires requests-ntlm)")
    elif findings.get("kerberos_detected"):
        print(f"  → {bold('kerberos')}  (requires requests-kerberos + kinit)")
    elif findings.get("oauth_discovery"):
        print(f"  → {bold('oauth2_client_creds')}  (or bearer with pre-obtained token)")
    elif findings.get("token_login_likely"):
        print(f"  → {bold('token_login')}  (POST creds to {findings.get('token_login_url','')})")
    elif findings.get("form_login"):
        print(f"  → {bold('form_login')}  (POST creds to login form)")
    elif findings.get("basic_auth"):
        print(f"  → {bold('basic')}  (HTTP Basic Auth)")
    elif findings.get("session_cookies"):
        print(f"  → {bold('session_cookie')}  (inject pre-captured cookie)")
    elif findings.get("api_key_header_hints"):
        print(f"  → {bold('apikey_header')}  (set key in request header)")
    else:
        print(f"  → {yellow('unknown')}  (manual inspection recommended)")


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="authprobe.py",
        description="AuthProbe — Detect & probe authentication methods on web apps and APIs",
    )
    parser.add_argument("--url",        metavar="URL",    required=True,  help="Target URL to probe")
    parser.add_argument("--type",       metavar="TYPE",   default="auto",
                        choices=["auto", "webapp", "api"],
                        help="Target type: auto (default), webapp, or api")
    parser.add_argument("--username",   metavar="USER",   default="",     help="Username for credential validation")
    parser.add_argument("--password",   metavar="PASS",   default="",     help="Password for credential validation")
    parser.add_argument("--token",      metavar="TOKEN",  default="",     help="Bearer token for credential validation")
    parser.add_argument("--proxy",      metavar="PROXY",  default="",     help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--timeout",    metavar="SEC",    type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--deep",       action="store_true",              help="Probe more login endpoint paths")
    parser.add_argument("--json",       action="store_true",              help="Output results as JSON")
    parser.add_argument("--no-verify",  action="store_true",              help="Disable SSL verification (default: disabled)")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    parsed   = urlparse(base_url)
    if not parsed.scheme:
        base_url = "https://" + base_url
        parsed   = urlparse(base_url)

    sess = _make_session(args)

    # ── Auto-detect type ──────────────────────────────────────
    probe_type = args.type
    if probe_type == "auto":
        # Heuristic: path contains /api/ or /v1/ or /v2/
        path = parsed.path.lower()
        if re.search(r'/api/|/v\d+/', path) or "api." in parsed.netloc.lower():
            probe_type = "api"
        else:
            probe_type = "webapp"
    print(f"  {dim('Target:')} {cyan(base_url)}")
    print(f"  {dim('Mode  :')} {cyan(probe_type)}")
    print()

    findings: dict = {
        "www_authenticate":    [],
        "form_login":          False,
        "form_login_evidence": [],
        "token_login_likely":  False,
        "token_login_url":     "",
        "oauth_discovery":     [],
        "session_cookies":     [],
        "api_key_header_hints": [],
        "login_endpoints":     [],
        "security_headers":    {},
        "basic_auth":          None,
        "ntlm_detected":       False,
        "kerberos_detected":   False,
        "validation_results":  [],
    }

    # ── Phase 1: probe base URL ─────────────────────���─────────
    print(f"  {dim('[1/4]')} Probing base URL…")
    base_resp = _safe_get(sess, base_url, args.timeout)

    detect_www_authenticate(base_resp, findings)
    detect_basic_auth(base_resp, findings)
    detect_ntlm_kerberos(base_resp, findings)
    detect_form_login(base_resp, findings)
    detect_session_cookies(base_resp, findings)
    detect_security_headers(base_resp, findings)

    # ── Phase 2: probe login endpoints ────────────────────────
    print(f"  {dim('[2/4]')} Probing login endpoints…")
    detect_login_endpoints(sess, base_url, args.timeout, probe_type, findings)

    # ── Phase 3: OAuth/OIDC discovery ────────────────────────��
    print(f"  {dim('[3/4]')} Checking OAuth/OIDC discovery…")
    detect_oauth_discovery(sess, base_url, args.timeout, findings)

    # ── Phase 4: Credential validation (optional) ─────────────
    print(f"  {dim('[4/4]')} Credential validation…")
    if args.username and args.password:
        if findings.get("basic_auth") is not None:
            result = validate_basic(sess, base_url, args.username, args.password, args.timeout)
            findings["validation_results"].append(result)

        if findings.get("form_login") and findings.get("login_endpoints"):
            for ep in findings["login_endpoints"]:
                if ep["status"] in (200, 302):
                    login_url = base_url + ep["path"]
                    result = validate_form_login(sess, login_url, args.username, args.password, args.timeout)
                    findings["validation_results"].append(result)
                    break

    if args.token:
        result = validate_bearer(sess, base_url, args.token, args.timeout)
        findings["validation_results"].append(result)

    # ── Output ────────────────────────────────────────────────
    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, args)
        print(f"\n{dim('─' * 60)}")
        print(f"  {dim('AuthProbe v' + VERSION + ' complete')}")
        print()


if __name__ == "__main__":
    main()

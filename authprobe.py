#!/usr/bin/env python3
"""
authprobe.py — Authentication Detection & Probing Tool

Probes a target URL (web application or API) to detect authentication methods
in use and optionally validates credentials for each method.

Usage:
    python3 authprobe.py --url https://target.com [options]
    python3 authprobe.py --url https://api.target.com/auth/login --username u --password p
"""

import argparse
import json
import re
import sys
import warnings
from urllib.parse import urlparse

VERSION = "1.3.0"

# Suppress SSL warnings for testing
warnings.filterwarnings("ignore")

BANNER = r"""
 ┌─────────────────────────────────────────────────────────┐
 │                                                         │
 │   █████╗ ██╗   ██╗████████╗██╗  ██╗                    │
 │  ██╔══██╗██║   ██║╚══██╔══╝██║  ██║                    │
 │  ███████║██║   ██║   ██║   ███████║                    │
 │  ██╔══██║██║   ██║   ██║   ██╔══██║                    │
 │  ██║  ██║╚██████╔╝   ██║   ██║  ██║                    │
 │  ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝                    │
 │                                                         │
 │  ██████╗ ██████╗  ██████╗ ██████╗ ███████╗             │
 │  ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝             │
 │  ██████╔╝██████╔╝██║   ██║██████╔╝█████╗               │
 │  ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝               │
 │  ██║     ██║  ██║╚██████╔╝██████╔╝███████╗             │
 │  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝             │
 │                                                         │
 │  Authentication Detection & Probing Tool  v{ver:<7}    │
 │  For authorized security testing only                   │
 └─────────────────────────────────────────────────────────┘
""".format(ver=VERSION)

# ─────────────────────────────────────────────────────────────
# Colour helpers
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


# ─────────────────────────────────────────────────────────────
# Detection signatures
# ─────────────────────────────────────────────────────────────

_WWW_AUTH_MAP = {
    "basic":     "HTTP Basic",
    "digest":    "HTTP Digest",
    "bearer":    "Bearer Token",
    "ntlm":      "NTLM",
    "negotiate": "Kerberos/SPNEGO",
    "oauth":     "OAuth",
}

_FORM_LOGIN_PATTERNS = [
    re.compile(r'<input[^>]+type=["\']password["\']', re.I),
    re.compile(r'<form[^>]+action=["\'][^"\']*log[^"\']*["\']', re.I),
    re.compile(r'<form[^>]+action=["\'][^"\']*sign.?in[^"\']*["\']', re.I),
    re.compile(r'<form[^>]+action=["\'][^"\']*auth[^"\']*["\']', re.I),
    re.compile(r'id=["\']login', re.I),
    re.compile(r'id=["\']signin', re.I),
    re.compile(r'name=["\']password["\']', re.I),
]

# JSON response keys that indicate a successful token response
_TOKEN_RESPONSE_KEYS = {
    "access_token", "token", "jwt", "id_token", "auth_token",
    "bearer", "sessionToken", "accessToken", "idToken", "authToken",
}

# JSON body patterns indicating an auth-protected endpoint (error responses)
_JSON_AUTH_ERROR_PATTERNS = [
    re.compile(r'"(message|error|msg)"\s*:\s*"[^"]*(?:unauthorized|unauthenticated|'
               r'not authenticated|authentication required|invalid.*(?:cred|pass|token)|'
               r'login required|access denied)[^"]*"', re.I),
    re.compile(r'"code"\s*:\s*"[^"]*(?:auth|unauthorized|unauthenticated|'
               r'invalid_credentials|login_required)[^"]*"', re.I),
    re.compile(r'"status"\s*:\s*"(?:unauthorized|unauthenticated)"', re.I),
    re.compile(r'"(code|status)"\s*:\s*40[13]', re.I),
]

# JSON body patterns indicating credentials were checked (wrong creds, not missing)
_JSON_CRED_FAILURE_PATTERNS = [
    re.compile(r'"(message|error|msg)"\s*:\s*"[^"]*(?:invalid.*(?:username|password|cred)|'
               r'wrong.*(?:username|password)|incorrect.*(?:username|password)|'
               r'authentication failed|login failed)[^"]*"', re.I),
    re.compile(r'"code"\s*:\s*"[^"]*(?:invalid_cred|wrong_cred|auth.*fail|'
               r'authentication_failed)[^"]*"', re.I),
]

# JSON body patterns indicating credentials were VALID but MFA is required
_JSON_MFA_PATTERNS = [
    re.compile(r'"code"\s*:\s*"[^"]*(?:mfa|2fa|otp|totp|two.?factor|'
               r'multi.?factor)[^"]*(?:required|needed|challenge)[^"]*"', re.I),
    re.compile(r'"code"\s*:\s*"[^"]*(?:required|needed|challenge)[^"]*(?:mfa|2fa|otp|'
               r'totp|two.?factor|multi.?factor)[^"]*"', re.I),
    # Exact common codes
    re.compile(r'"code"\s*:\s*"(?:MFA_AUTH_REQUIRED|MFA_REQUIRED|2FA_REQUIRED|'
               r'OTP_REQUIRED|TOTP_REQUIRED|MFA_NEEDED|TWO_FACTOR_REQUIRED|'
               r'MULTIFACTOR_REQUIRED|MFA_CHALLENGE|AUTH_MFA_REQUIRED)"', re.I),
    re.compile(r'"(message|msg)"\s*:\s*"[^"]*(?:mfa|two.?factor|multi.?factor|'
               r'second.?factor|authenticat[a-z]*\s+(?:app|code|token))[^"]*required[^"]*"',
               re.I),
    re.compile(r'"required"\s*:\s*"(?:2fa|mfa|totp|otp)"', re.I),
    re.compile(r'"authenticators"\s*:\s*\[', re.I),
    re.compile(r'"mfaCookie"\s*:', re.I),
    re.compile(r'"mfa_cookie"\s*:', re.I),
]

# URL path patterns that indicate a login/auth endpoint
_LOGIN_PATH_RE = re.compile(
    r'/(auth/login|auth/token|auth/signin|api/auth|api/login|api/signin|'
    r'api/token|oauth/token|connect/token|login|signin|sign-in|'
    r'v\d+/auth|v\d+/login|user[s]?/login|account/login|session[s]?)',
    re.I,
)

_SESSION_COOKIE_NAMES = re.compile(
    r'(session|sess|auth|jwt|token|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|'
    r'connect\.sid|sid|sso|remember_me)',
    re.I,
)

_API_KEY_HEADERS = re.compile(
    r'(X-API-Key|X-Auth-Token|X-Access-Token|X-App-Key|X-App-Token|'
    r'API-Key|X-RapidAPI-Key)',
    re.I,
)

_OAUTH_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

_LOGIN_PROBE_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/auth/login",
    "/api/login", "/api/auth", "/api/auth/login", "/api/signin",
    "/api/token", "/oauth/token", "/connect/token",
    "/v1/auth", "/v1/login", "/v2/auth", "/v2/login",
    "/user/login", "/users/login", "/account/login",
    "/api/v1/auth", "/api/v1/login", "/api/v2/auth", "/api/v2/login",
    "/api/v1/auth/login", "/api/v2/auth/login",
]

# Common field name combos for form/JSON login probing
_CRED_FIELD_COMBOS = [
    ("username", "password"),
    ("email",    "password"),
    ("user",     "pass"),
    ("login",    "password"),
    ("name",     "password"),
]

# Field names to try when submitting a TOTP/OTP code
_MFA_CODE_FIELDS = [
    "code", "token", "otp", "totp", "mfa_code", "totp_code",
    "passcode", "pin", "one_time_password",
]

# Path suffixes appended to the parent of the login path when probing for MFA endpoint
_MFA_SUBMISSION_SUFFIXES = [
    "/mfa", "/2fa", "/otp", "/totp", "/verify",
    "/mfa/verify", "/mfa/validate", "/mfa/confirm",
    "/2fa/verify", "/auth/mfa", "/auth/2fa", "/auth/otp",
    "/auth/verify", "/auth/totp",
]


# ─────────────────────────────────────────────────────────────
# HTTP helpers
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
        "Accept": "application/json, text/html, */*",
    })
    if args.proxy:
        sess.proxies = {"http": args.proxy, "https": args.proxy}
    from requests.adapters import HTTPAdapter
    sess.mount("http://",  HTTPAdapter(max_retries=1))
    sess.mount("https://", HTTPAdapter(max_retries=1))
    return sess


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


def _is_json_response(resp) -> bool:
    if resp is None:
        return False
    ct = resp.headers.get("Content-Type", "").lower()
    return "json" in ct


def _json_body(resp) -> dict | None:
    if resp is None:
        return None
    try:
        return resp.json()
    except Exception:
        return None


def _nested_keys(d: dict) -> set:
    """Recursively collect all string keys and string values from a dict."""
    result = set()
    if not isinstance(d, dict):
        return result
    for k, v in d.items():
        result.add(str(k).lower())
        if isinstance(v, str):
            result.add(v.lower())
        elif isinstance(v, dict):
            result |= _nested_keys(v)
    return result


def _extract_mfa_types(body: dict) -> list:
    """Extract MFA authenticator types from a challenge response body."""
    types = []
    if not isinstance(body, dict):
        return types
    # data.authenticators[].type  OR  authenticators[].type (top-level)
    for key in ("authenticators",):
        data = body.get("data", {}) if isinstance(body.get("data"), dict) else {}
        auths = body.get(key) or data.get(key) or []
        if isinstance(auths, list):
            for a in auths:
                t = (a.get("type") or "") if isinstance(a, dict) else ""
                if t and t not in types:
                    types.append(t)
    return types


def _is_mfa_challenge(resp, body_text: str = "") -> bool:
    """Return True if the response body signals a valid-credential MFA challenge."""
    for pat in _JSON_MFA_PATTERNS:
        if pat.search(body_text):
            return True
    return False


# ─────────────────────────────────────────────────────────────
# URL analysis
# ─────────────────────────────────────────────────────────────

def _split_url(url: str) -> tuple[str, str, str]:
    """Return (origin, path, full_url). Origin = scheme://host[:port]."""
    p = urlparse(url)
    port_part = f":{p.port}" if p.port and p.port not in (80, 443) else ""
    origin = f"{p.scheme}://{p.hostname}{port_part}"
    return origin, p.path, url


def _is_login_path(path: str) -> bool:
    return bool(_LOGIN_PATH_RE.search(path))


# ─────────────────────────────────────────────────────────────
# TOTP / MFA helpers
# ─────────────────────────────────────────────────────────────

def _generate_totp(secret: str) -> "str | None":
    """Generate current TOTP code using pyotp. Returns None if pyotp unavailable."""
    try:
        import pyotp
        return pyotp.TOTP(secret.strip().upper()).now()
    except ImportError:
        return None
    except Exception:
        return None


def _extract_mfa_cookie(body: "dict | None", resp) -> "tuple[str, str]":
    """Return (cookie_name, cookie_value) from an MFA challenge response.

    Checks (in order):
    1. body["mfaCookie"] or body["data"]["mfaCookie"] — value is "NAME=JWT" or bare JWT
    2. body["mfa_cookie"] / body["data"]["mfa_cookie"]
    3. Set-Cookie response headers matching MFA name patterns
    """
    _mfa_keys = ("mfaCookie", "mfa_cookie", "mfa_token", "challengeCookie")
    _sources: list = [body or {}]
    if isinstance((body or {}).get("data"), dict):
        _sources.append(body["data"])

    for src in _sources:
        for key in _mfa_keys:
            val = src.get(key, "")
            if val and isinstance(val, str):
                if "=" in val and not val.startswith("eyJ"):
                    # "NAME=VALUE" format
                    name, _, value = val.partition("=")
                    return name.strip(), value.strip()
                # Bare JWT — use the key name as cookie name
                return key, val

    # Fallback: inspect Set-Cookie headers
    if resp is not None:
        for raw in resp.headers.get("Set-Cookie", "").split(","):
            part = raw.strip().split(";")[0]  # cookie name=value only
            if re.search(r'(2fa|mfa|otp|totp|challenge)', part, re.I) and "=" in part:
                name, _, value = part.partition("=")
                return name.strip(), value.strip()
    return "", ""


def _extract_default_totp_id(body: "dict | None") -> str:
    """Return the ID of the TOTP authenticator from a challenge body, or ''."""
    if not isinstance(body, dict):
        return ""
    data = body.get("data", {}) if isinstance(body.get("data"), dict) else body
    auths = data.get("authenticators", [])
    if not isinstance(auths, list):
        return ""
    for a in auths:
        if isinstance(a, dict) and a.get("type", "").lower() == "totp":
            return str(a.get("id", ""))
    return ""


def _mfa_submission_paths(login_path: str) -> list:
    """Derive candidate MFA submission endpoint paths from the login path."""
    login_path = login_path.rstrip("/")
    # Parent directory (strip last segment, e.g. /api/auth/login → /api/auth)
    parent = "/".join(login_path.split("/")[:-1]) or "/"
    seen: set = set()
    paths: list = []

    def _add(p: str) -> None:
        p = p.rstrip("/") or "/"
        if p not in seen:
            seen.add(p)
            paths.append(p)

    # Parent + common MFA suffixes (highest priority)
    for sfx in _MFA_SUBMISSION_SUFFIXES:
        _add(parent + sfx)
    # Login path itself + common MFA suffixes
    for sfx in _MFA_SUBMISSION_SUFFIXES:
        _add(login_path + sfx)
    return paths


def complete_totp(
    sess,
    origin: str,
    login_path: str,
    mfa_cookie_name: str,
    mfa_cookie_value: str,
    totp_code: str,
    authenticator_id: str,
    timeout: int,
) -> dict:
    """Attempt to complete a TOTP MFA challenge.

    Probes candidate MFA endpoints derived from *login_path*, submitting
    *totp_code* in various field names. The *mfa_cookie* is set on the session
    before each attempt so the server can correlate the MFA step with the
    credential step.

    Returns a result dict with at minimum: method, success, status, evidence.
    """
    result: dict = {
        "method":   "totp_mfa",
        "success":  False,
        "status":   None,
        "evidence": "",
    }

    if not totp_code:
        result["evidence"] = "No TOTP code generated (check --totp-secret format)"
        return result

    candidate_paths = _mfa_submission_paths(login_path)

    for path in candidate_paths:
        url = origin.rstrip("/") + path

        # Attach MFA session cookie before each attempt
        if mfa_cookie_name and mfa_cookie_value:
            sess.cookies.set(mfa_cookie_name, mfa_cookie_value,
                             domain=urlparse(origin).hostname or "")

        for field in _MFA_CODE_FIELDS:
            payload: dict = {field: totp_code}
            if authenticator_id:
                payload["authenticator_id"] = authenticator_id

            r = _safe_post(sess, url, timeout,
                           json=payload,
                           headers={"Content-Type": "application/json",
                                    "Accept": "application/json"})
            if r is None:
                continue

            result["status"] = r.status_code
            body      = _json_body(r)
            body_text = r.text or ""

            # ── Success: token key in body ──────────────────────
            if r.status_code in (200, 201) and isinstance(body, dict):
                all_keys = _nested_keys(body)
                matched  = all_keys & {k.lower() for k in _TOKEN_RESPONSE_KEYS}
                if matched:
                    result.update({
                        "success":    True,
                        "token_keys": list(matched),
                        "endpoint":   url,
                        "field":      field,
                        "evidence":   (
                            f"TOTP accepted — token key(s) found: {matched} "
                            f"(endpoint: {url}, field: '{field}')"
                        ),
                    })
                    return result

                # 200 with no token key — check for new session cookies
                if r.status_code == 200 and not any(
                    pat.search(body_text) for pat in
                    _JSON_AUTH_ERROR_PATTERNS + _JSON_CRED_FAILURE_PATTERNS
                ):
                    new_cookies = [
                        c.name for c in sess.cookies
                        if _SESSION_COOKIE_NAMES.search(c.name)
                    ]
                    if new_cookies:
                        result.update({
                            "success":  True,
                            "endpoint": url,
                            "field":    field,
                            "evidence": (
                                f"TOTP accepted — session cookie(s) set: "
                                f"{new_cookies} (endpoint: {url}, field: '{field}')"
                            ),
                        })
                        return result

            # ── Endpoint found but code rejected ─────────────────
            if r.status_code in (400, 401, 403, 422):
                if re.search(
                    r'(invalid|wrong|incorrect|expired|bad).*(?:code|token|otp|totp|pin)',
                    body_text, re.I
                ):
                    result.update({
                        "success":             False,
                        "totp_endpoint_found": True,
                        "endpoint":            url,
                        "field":               field,
                        "evidence": (
                            f"TOTP endpoint found but code rejected — HTTP {r.status_code} "
                            f"(endpoint: {url}, field: '{field}'). "
                            "The code may have expired; re-run with a fresh --totp-secret."
                        ),
                    })
                    return result

    result["evidence"] = (
        f"No MFA submission endpoint responded to TOTP code "
        f"(tried {len(candidate_paths)} path(s)). "
        "Endpoint path may be non-standard — try --url with the MFA path directly."
    )
    return result


# ─────────────────────────────────────────────────────────────
# Detectors
# ─────────────────────────────────────────────────────────────

def detect_www_authenticate(resp, findings: dict):
    if resp is None:
        return
    if resp.status_code not in (401, 403):
        return
    www_auth = resp.headers.get("WWW-Authenticate", "")
    if not www_auth:
        return
    for part in www_auth.split(","):
        part = part.strip()
        scheme = part.split()[0].lower() if part else ""
        if scheme:
            label = _WWW_AUTH_MAP.get(scheme, f"Unknown ({scheme})")
            findings["www_authenticate"].append({"scheme": scheme, "label": label, "header": www_auth})


def detect_basic_auth(resp, findings: dict):
    if resp is None:
        return
    www_auth = resp.headers.get("WWW-Authenticate", "").lower()
    if www_auth.startswith("basic"):
        m = re.search(r'realm=["\']([^"\']+)["\']', www_auth, re.I)
        findings["basic_auth"] = {"realm": m.group(1) if m else ""}


def detect_ntlm_kerberos(resp, findings: dict):
    if resp is None:
        return
    www_auth = resp.headers.get("WWW-Authenticate", "").lower()
    if "ntlm" in www_auth:
        findings["ntlm_detected"] = True
    if "negotiate" in www_auth:
        findings["kerberos_detected"] = True


def detect_form_login(resp, findings: dict):
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


def detect_json_api_auth(resp, url: str, findings: dict):
    """Detect JSON API authentication by inspecting the response body and status.

    Handles the common REST API pattern where the server returns a JSON error
    body without a WWW-Authenticate header — e.g.:
      {"error":{"code":401,"message":"Unauthorized"}}
      {"message":"Invalid username or password","code":"AUTHENTICATION_FAILED_..."}
    """
    if resp is None:
        return
    if not _is_json_response(resp) and resp.status_code not in (400, 401, 403, 422):
        return

    body_text = resp.text or ""
    body_json  = _json_body(resp)

    # 1. HTTP 401/403 with JSON body → definitely auth-protected
    if resp.status_code in (401, 403) and (body_json or body_text.strip().startswith("{")):
        findings["json_api_auth"] = True
        findings["json_api_auth_url"] = url
        # Check if this specific response indicates a credential check
        # (i.e. creds were actually evaluated, not just missing)
        for pat in _JSON_CRED_FAILURE_PATTERNS:
            if pat.search(body_text):
                findings["json_api_cred_checked"] = True
                break
        return

    # 2. HTTP 200/400/422 — scan body for auth error patterns
    for pat in _JSON_AUTH_ERROR_PATTERNS:
        if pat.search(body_text):
            findings["json_api_auth"] = True
            findings["json_api_auth_url"] = url
            break

    # 3. Check for credential-failure-specific patterns
    if not findings.get("json_api_cred_checked"):
        for pat in _JSON_CRED_FAILURE_PATTERNS:
            if pat.search(body_text):
                findings["json_api_auth"] = True
                findings["json_api_auth_url"] = url
                findings["json_api_cred_checked"] = True
                break


def detect_token_login_response(resp, url: str, findings: dict):
    """Check if the response contains a JSON token (successful login response)."""
    if not _is_json_response(resp):
        return
    body = _json_body(resp)
    if not isinstance(body, dict):
        return
    all_keys = _nested_keys(body)
    if all_keys & {k.lower() for k in _TOKEN_RESPONSE_KEYS}:
        findings["token_login_likely"] = True
        findings["token_login_url"] = url


def detect_session_cookies(resp, findings: dict):
    if resp is None:
        return
    for cookie in resp.cookies:
        if _SESSION_COOKIE_NAMES.search(cookie.name):
            findings["session_cookies"].append(cookie.name)


def detect_security_headers(resp, findings: dict):
    if resp is None:
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}
    sec = {}
    for h in ("x-frame-options", "content-security-policy",
               "strict-transport-security", "x-content-type-options"):
        if h in headers:
            val = headers[h]
            sec[h.title()] = val[:80] + "…" if len(val) > 80 else val
    if sec:
        findings["security_headers"] = sec
    for h in resp.headers:
        if _API_KEY_HEADERS.search(h):
            findings["api_key_header_hints"].append(h)


def detect_oauth_discovery(sess, origin: str, timeout: int, findings: dict):
    for path in _OAUTH_DISCOVERY_PATHS:
        url = origin.rstrip("/") + path
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


def detect_login_endpoints(sess, origin: str, timeout: int, probe_type: str,
                           skip_paths: set, findings: dict):
    """Probe common login paths from the API origin root."""
    found = []
    for path in _LOGIN_PROBE_PATHS:
        if path.rstrip("/") in skip_paths:
            continue
        if probe_type == "webapp" and path.startswith("/api/"):
            continue
        url = origin.rstrip("/") + path
        r = _safe_get(sess, url, timeout)
        if r and r.status_code in (200, 301, 302, 400, 401, 403, 422):
            found.append({
                "path": path,
                "status": r.status_code,
                "content_type": r.headers.get("Content-Type", "")[:60],
            })
            detect_json_api_auth(r, url, findings)
            detect_token_login_response(r, url, findings)
            if probe_type == "webapp":
                detect_form_login(r, findings)
    if found:
        existing = {ep["path"] for ep in findings.get("login_endpoints", [])}
        for ep in found:
            if ep["path"] not in existing:
                findings["login_endpoints"].append(ep)


# ─────────────────────────────────────────────────────────────
# Credential validation
# ─────────────────────────────────────────────────────────────

def validate_basic(sess, url: str, username: str, password: str, timeout: int) -> dict:
    r = _safe_get(sess, url, timeout, auth=(username, password))
    ok = r is not None and r.status_code not in (401, 403)
    return {"method": "basic", "success": ok,
            "status": r.status_code if r else None}


def validate_bearer(sess, url: str, token: str, timeout: int) -> dict:
    import copy
    s2 = copy.copy(sess)
    s2.headers = dict(sess.headers)
    s2.headers["Authorization"] = f"Bearer {token}"
    r = _safe_get(s2, url, timeout)
    ok = r is not None and r.status_code not in (401, 403)
    return {"method": "bearer", "success": ok,
            "status": r.status_code if r else None}


def validate_token_login(sess, login_url: str, username: str, password: str,
                         timeout: int) -> dict:
    """POST JSON credentials to a login endpoint; check for token in response."""
    best: dict = {"method": "token_login", "success": False,
                  "status": None, "evidence": ""}

    for ufield, pfield in _CRED_FIELD_COMBOS:
        payload = {ufield: username, pfield: password}
        r = _safe_post(sess, login_url, timeout,
                       json=payload,
                       headers={"Content-Type": "application/json",
                                "Accept": "application/json"})
        if r is None:
            continue
        best["status"] = r.status_code
        body      = _json_body(r)
        body_text = r.text or ""

        # MFA challenge — credentials were valid; server wants a second factor
        if _is_mfa_challenge(r, body_text):
            mfa_types = _extract_mfa_types(body) if isinstance(body, dict) else []
            cookie_name, cookie_value = _extract_mfa_cookie(body, r)
            totp_id = _extract_default_totp_id(body)
            best.update({
                "success":              True,
                "mfa_required":         True,
                "mfa_types":            mfa_types,
                "mfa_cookie_name":      cookie_name,
                "mfa_cookie_value":     cookie_value,
                "totp_authenticator_id": totp_id,
                "evidence":      (
                    f"Credentials accepted — MFA challenge issued "
                    f"(HTTP {r.status_code}, field combo: {ufield}/{pfield})"
                    + (f". MFA types: {', '.join(mfa_types)}" if mfa_types else "")
                ),
                "field_combo":   f"{ufield}/{pfield}",
            })
            return best

        # Successful login — token in body
        if r.status_code in (200, 201) and isinstance(body, dict):
            all_keys = _nested_keys(body)
            matched = all_keys & {k.lower() for k in _TOKEN_RESPONSE_KEYS}
            if matched:
                best.update({
                    "success": True,
                    "evidence": f"token key(s) found: {matched}",
                    "field_combo": f"{ufield}/{pfield}",
                    "token_keys": list(matched),
                })
                return best

        # Auth endpoint confirmed — wrong creds
        if r.status_code in (400, 401, 403, 422):
            for pat in _JSON_CRED_FAILURE_PATTERNS:
                if pat.search(body_text):
                    best.update({
                        "success": False,
                        "evidence": (f"Login endpoint confirmed — credentials rejected "
                                     f"(HTTP {r.status_code}). "
                                     f"Field combo tried: {ufield}/{pfield}"),
                        "field_combo": f"{ufield}/{pfield}",
                        "endpoint_confirmed": True,
                    })
                    return best
            # Generic 401/403 on POST = endpoint exists, creds wrong
            if r.status_code in (401, 403) and _is_json_response(r):
                best.update({
                    "success": False,
                    "evidence": (f"Login endpoint confirmed — HTTP {r.status_code} "
                                 f"(field combo: {ufield}/{pfield})"),
                    "field_combo": f"{ufield}/{pfield}",
                    "endpoint_confirmed": True,
                })
                return best

    return best


def validate_form_login(sess, login_url: str, username: str, password: str,
                        timeout: int) -> dict:
    for ufield, pfield in _CRED_FIELD_COMBOS:
        r = _safe_post(sess, login_url, timeout,
                       data={ufield: username, pfield: password})
        if r is None:
            continue
        if r.status_code not in (401, 403) and r.url != login_url:
            return {"method": "form_login", "success": True,
                    "status": r.status_code, "redirected_to": r.url}
        if r.status_code == 200:
            body = r.text.lower()
            if any(k in body for k in ("logout", "dashboard", "welcome", "sign out")):
                return {"method": "form_login", "success": True,
                        "status": r.status_code, "evidence": "logout/welcome text found"}
    return {"method": "form_login", "success": False,
            "status": r.status_code if r else None}


# ─────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────

def _print_section(title):
    print(f"\n{bold(cyan('━' * 60))}")
    print(f"  {bold(title)}")
    print(f"{bold(cyan('━' * 60))}")


def _print_findings(findings: dict, args):
    detected = []

    if findings.get("basic_auth") is not None:
        realm = (findings["basic_auth"] or {}).get("realm", "")
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
        detected.append(("Form-based Login",
                          f"{len(evidence)} HTML form pattern(s) matched"))

    if findings.get("json_api_auth"):
        url = findings.get("json_api_auth_url", "")
        cred_note = " — credentials evaluated (endpoint confirmed)" \
                    if findings.get("json_api_cred_checked") else ""
        detected.append(("JSON API Token Login",
                          f"endpoint: {url}{cred_note}"))

    if findings.get("token_login_likely"):
        url = findings.get("token_login_url", "")
        if findings.get("mfa_required"):
            mfa_types = ", ".join(findings.get("mfa_types", [])) or "unknown"
            detected.append(("Token / JWT Login API + MFA",
                              f"endpoint: {url} — MFA types: {mfa_types}"))
        else:
            detected.append(("Token / JWT Login API", f"endpoint: {url}"))

    for entry in findings.get("oauth_discovery", []):
        detected.append(("OAuth2 / OIDC",
                          f"issuer: {entry.get('issuer','?')} | "
                          f"token_ep: {entry.get('token_endpoint','?')}"))

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
            sc = ep["status"]
            colour = green if sc in (200, 302) else yellow
            print(f"  {colour(str(sc))}  {ep['path']}  {dim(ep['content_type'])}")

    if findings.get("security_headers"):
        _print_section("SECURITY HEADERS")
        for k, v in findings["security_headers"].items():
            print(f"  {cyan(k)}: {dim(v)}")

    if findings.get("validation_results"):
        _print_section("CREDENTIAL VALIDATION")
        for r in findings["validation_results"]:
            ok       = r.get("success", False)
            mfa_req  = r.get("mfa_required", False)
            meth     = r.get("method", "?")
            sc       = r.get("status", "?")
            extra    = r.get("evidence", r.get("redirected_to", ""))

            if meth == "totp_mfa":
                if ok:
                    icon = green("✓ TOTP ACCEPTED")
                elif r.get("totp_endpoint_found"):
                    icon = yellow("~ TOTP ENDPOINT FOUND (code rejected)")
                else:
                    icon = red("✗ TOTP FAILED")
                ep = r.get("endpoint", "")
                sc_str = f"  status={sc}" if sc else ""
                print(f"  {icon}{sc_str}")
                if ep:
                    print(f"       {dim('endpoint: ' + ep)}")
            elif mfa_req:
                mfa_types = r.get("mfa_types", [])
                mfa_label = f"  [{', '.join(mfa_types)}]" if mfa_types else ""
                icon = green(f"✓ VALID — MFA Required{mfa_label}")
                print(f"  {icon}  method={bold(meth)}  status={sc}")
            elif ok:
                icon = green("✓ VALID")
                print(f"  {icon}  method={bold(meth)}  status={sc}")
            elif r.get("endpoint_confirmed"):
                icon = yellow("~ CONFIRMED (wrong creds)")
                print(f"  {icon}  method={bold(meth)}  status={sc}")
            else:
                icon = red("✗ FAILED")
                print(f"  {icon}  method={bold(meth)}  status={sc}")

            if extra:
                print(f"       {dim(extra)}")

    _print_section("RECOMMENDED AUTH METHOD FOR FRACTURE / SIPHON")
    if findings.get("ntlm_detected"):
        print(f"  → {bold('ntlm')}  (requires requests-ntlm)")
    elif findings.get("kerberos_detected"):
        print(f"  → {bold('kerberos')}  (requires requests-kerberos + kinit)")
    elif findings.get("oauth_discovery"):
        print(f"  → {bold('oauth2_client_creds')}  (or bearer with pre-obtained token)")
    elif findings.get("token_login_likely"):
        url = findings.get("token_login_url", "")
        print(f"  → {bold('token_login')}  (POST credentials to {url})")
    elif findings.get("json_api_auth"):
        url = findings.get("json_api_auth_url", "")
        print(f"  → {bold('token_login')}  (POST credentials to {url})")
    elif findings.get("form_login"):
        print(f"  → {bold('form_login')}  (POST credentials to login form)")
    elif findings.get("basic_auth") is not None:
        print(f"  → {bold('basic')}  (HTTP Basic Auth)")
    elif findings.get("session_cookies"):
        print(f"  → {bold('session_cookie')}  (inject pre-captured cookie)")
    elif findings.get("api_key_header_hints"):
        print(f"  → {bold('apikey_header')}  (set key in request header)")
    else:
        print(f"  → {yellow('unknown')}  (manual inspection recommended)")

    # Siphon/Fracture config snippet
    if findings.get("json_api_auth") or findings.get("token_login_likely"):
        url = findings.get("token_login_url") or findings.get("json_api_auth_url", "")
        vr  = findings.get("validation_results", [])
        tl  = next((r for r in vr if r.get("method") == "token_login"), None)
        combo_hint = f"  # field combo: {tl['field_combo']}" if tl and tl.get("field_combo") else ""
        print(f"\n  {dim('Siphon config snippet:')}")
        print(f'  {dim("scan.auth.method")}           = {cyan("token_login")}')
        print(f'  {dim("scan.auth.login_url")}        = {cyan(url)}')
        if combo_hint:
            print(f'  {dim(combo_hint)}')


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="authprobe.py",
        description="AuthProbe — Detect & probe authentication methods on web apps and APIs",
    )
    parser.add_argument("--url",       metavar="URL",   required=True,
                        help="Target URL (can be root, a login endpoint, or a protected path)")
    parser.add_argument("--type",      metavar="TYPE",  default="auto",
                        choices=["auto", "webapp", "api"],
                        help="Target type: auto (default), webapp, or api")
    parser.add_argument("--username",  metavar="USER",  default="",
                        help="Username for credential validation")
    parser.add_argument("--password",  metavar="PASS",  default="",
                        help="Password for credential validation")
    parser.add_argument("--token",       metavar="TOKEN",  default="",
                        help="Bearer token for credential validation")
    parser.add_argument("--totp-secret", metavar="SECRET", default="",
                        help="Base32 TOTP secret — auto-completes MFA challenge after valid credentials")
    parser.add_argument("--proxy",     metavar="PROXY", default="",
                        help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--timeout",   metavar="SEC",   type=int, default=10,
                        help="Request timeout in seconds")
    parser.add_argument("--json",      action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL verification (already disabled by default)")
    args = parser.parse_args()

    raw_url = args.url.rstrip("/")
    parsed  = urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "https://" + raw_url
        parsed  = urlparse(raw_url)

    # ── Determine origin vs. login path ──────────────────────
    origin, url_path, full_url = _split_url(raw_url)

    # If the given URL path looks like a login endpoint, use it directly
    # and derive origin for OAuth/general probing.
    given_is_login_path = _is_login_path(url_path)
    probe_root          = origin if given_is_login_path else full_url
    direct_login_url    = full_url if given_is_login_path else None
    # Paths already known (don't re-probe them from root)
    skip_paths: set = {url_path.rstrip("/")} if given_is_login_path else set()

    # ── Auto-detect type ──────────────────────────────────────
    probe_type = args.type
    if probe_type == "auto":
        path_lc = url_path.lower()
        if re.search(r'/api/|/v\d+/', path_lc) or "api." in parsed.netloc.lower():
            probe_type = "api"
        else:
            probe_type = "webapp"

    print(f"  {dim('Target :')} {cyan(full_url)}")
    print(f"  {dim('Origin :')} {cyan(origin)}")
    print(f"  {dim('Mode   :')} {cyan(probe_type)}")
    if given_is_login_path:
        print(f"  {dim('Note   :')} {yellow('Provided URL appears to be a login endpoint — probing directly')}")
    print()

    findings: dict = {
        "www_authenticate":       [],
        "form_login":             False,
        "form_login_evidence":    [],
        "json_api_auth":          False,
        "json_api_auth_url":      "",
        "json_api_cred_checked":  False,
        "token_login_likely":     False,
        "token_login_url":        "",
        "oauth_discovery":        [],
        "session_cookies":        [],
        "api_key_header_hints":   [],
        "login_endpoints":        [],
        "security_headers":       {},
        "basic_auth":             None,
        "ntlm_detected":          False,
        "kerberos_detected":      False,
        "validation_results":     [],
    }

    # ── Phase 1: Probe the provided URL ──────────────────────
    print(f"  {dim('[1/4]')} Probing target URL…")
    base_resp = _safe_get(sess := _make_session(args), full_url, args.timeout)

    detect_www_authenticate(base_resp, findings)
    detect_basic_auth(base_resp, findings)
    detect_ntlm_kerberos(base_resp, findings)
    detect_form_login(base_resp, findings)
    detect_json_api_auth(base_resp, full_url, findings)
    detect_token_login_response(base_resp, full_url, findings)
    detect_session_cookies(base_resp, findings)
    detect_security_headers(base_resp, findings)

    # If URL is a login path, record it immediately
    if given_is_login_path:
        findings["login_endpoints"].append({
            "path": url_path,
            "status": base_resp.status_code if base_resp else 0,
            "content_type": base_resp.headers.get("Content-Type", "")[:60] if base_resp else "",
        })

    # ── Phase 2: Probe root origin for additional endpoints ──
    print(f"  {dim('[2/4]')} Probing login endpoints from origin…")
    # Also probe the origin root itself if we were given a sub-path
    if given_is_login_path:
        root_resp = _safe_get(sess, origin, args.timeout)
        if root_resp:
            detect_www_authenticate(root_resp, findings)
            detect_basic_auth(root_resp, findings)
            detect_ntlm_kerberos(root_resp, findings)
            detect_form_login(root_resp, findings)
            detect_session_cookies(root_resp, findings)
    detect_login_endpoints(sess, origin, args.timeout, probe_type, skip_paths, findings)

    # ── Phase 3: OAuth/OIDC discovery ────────────────────────
    print(f"  {dim('[3/4]')} Checking OAuth/OIDC discovery…")
    detect_oauth_discovery(sess, origin, args.timeout, findings)

    # ── Phase 4: Credential validation ───────────────────────
    print(f"  {dim('[4/4]')} Credential validation…")

    if args.username and args.password:
        # Always try token_login against the login endpoint (direct or discovered)
        login_targets = []
        if direct_login_url:
            login_targets.append(direct_login_url)
        # Add any discovered login endpoints not already in login_targets
        for ep in findings.get("login_endpoints", []):
            ep_url = origin.rstrip("/") + ep["path"]
            if ep_url not in login_targets and ep["status"] in (200, 400, 401, 403, 422):
                login_targets.append(ep_url)

        for lt in login_targets[:3]:  # cap at 3 attempts
            result = validate_token_login(sess, lt, args.username, args.password, args.timeout)
            findings["validation_results"].append(result)
            if result.get("success") or result.get("endpoint_confirmed"):
                # Update detection findings based on validation results
                if result.get("success") and not result.get("mfa_required"):
                    findings["token_login_likely"] = True
                    findings["token_login_url"]    = lt
                elif result.get("mfa_required"):
                    findings["token_login_likely"] = True
                    findings["token_login_url"]    = lt
                    findings["mfa_required"]       = True
                    findings["mfa_types"]          = result.get("mfa_types", [])
                    # ── TOTP completion ──────────────────────────────
                    totp_secret = getattr(args, "totp_secret", "").strip()
                    if totp_secret and "totp" in [t.lower() for t in result.get("mfa_types", [])]:
                        totp_code = _generate_totp(totp_secret)
                        if totp_code:
                            print(f"  {dim('[4b/4]')} Completing TOTP MFA challenge…")
                            _, lt_path, _ = _split_url(lt)
                            totp_result = complete_totp(
                                sess, origin, lt_path,
                                result.get("mfa_cookie_name", ""),
                                result.get("mfa_cookie_value", ""),
                                totp_code,
                                result.get("totp_authenticator_id", ""),
                                args.timeout,
                            )
                            findings["validation_results"].append(totp_result)
                            if totp_result.get("success"):
                                findings["token_login_likely"] = True
                                findings["token_login_url"]    = totp_result.get("endpoint", lt)
                        else:
                            findings["validation_results"].append({
                                "method":   "totp_mfa",
                                "success":  False,
                                "status":   None,
                                "evidence": "pyotp not installed — run: pip install pyotp",
                            })
                    elif totp_secret:
                        # Secret provided but no totp in mfa_types — warn
                        findings["validation_results"].append({
                            "method":   "totp_mfa",
                            "success":  False,
                            "status":   None,
                            "evidence": (
                                f"--totp-secret provided but TOTP not in MFA types "
                                f"({result.get('mfa_types', [])}). "
                                "Skipping TOTP completion."
                            ),
                        })
                else:
                    findings["json_api_auth"]     = True
                    findings["json_api_auth_url"] = lt
                    findings["json_api_cred_checked"] = True
                break

        # HTTP Basic fallback
        if findings.get("basic_auth") is not None:
            result = validate_basic(sess, full_url, args.username, args.password, args.timeout)
            findings["validation_results"].append(result)

        # Form login fallback
        if findings.get("form_login"):
            for ep in findings.get("login_endpoints", []):
                if ep["status"] in (200, 302):
                    result = validate_form_login(
                        sess, origin.rstrip("/") + ep["path"],
                        args.username, args.password, args.timeout)
                    findings["validation_results"].append(result)
                    break

    if args.token:
        findings["validation_results"].append(
            validate_bearer(sess, full_url, args.token, args.timeout))

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

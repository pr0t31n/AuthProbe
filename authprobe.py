#!/usr/bin/env python3
"""
authprobe.py — Authentication Detection & Probing Tool

Probes a target URL (web application or API) to detect authentication methods
in use and optionally validates credentials for each method.  Also performs
software/portal fingerprinting to identify the target platform and improve
auth method recommendations.

Importable API::

    from authprobe import AuthProbe
    result = AuthProbe(timeout=10).probe("https://target.example.com")

CLI::

    python3 authprobe.py --url https://target.com [options]
    python3 authprobe.py --url https://api.target.com/auth/login --username u --password p
"""

import argparse
import json
import os
import re
import sys
import threading
import warnings
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

try:
    import os as _os_pp
    import sys as _sys_pp
    if "/opt/pr0t31n/shared" not in _sys_pp.path:
        _sys_pp.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_pause as _pp
except ImportError:
    _pp = None
_PAUSE = None

# ─────────────────────────────────────────────────────────────
# Console — protocol-aware logging for Crucible v2
# ─────────────────────────────────────────────────────────────
_CRUCIBLE_MANAGED = os.environ.get("CRUCIBLE_MANAGED", "") == "1"
_PRINT_LOCK = threading.Lock()


class AuthProbeConsole:
    def __init__(self):
        self._managed = _CRUCIBLE_MANAGED

    def log(self, message, level="INFO"):
        with _PRINT_LOCK:
            if self._managed:
                entry = {"ts": datetime.now().isoformat(), "level": level, "message": message}
                sys.stdout.write("__CRUCIBLE_LOG__:" + json.dumps(entry) + "\n")
                sys.stdout.flush()
            else:
                ts = datetime.now().strftime("%H:%M:%S")
                colors = {"INFO": "\033[36m", "SUCCESS": "\033[32m",
                          "WARNING": "\033[33m", "ERROR": "\033[31m"}
                tags = {"INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[~]", "ERROR": "[!]"}
                c = colors.get(level, "")
                tag = tags.get(level, "[*]")
                reset = "\033[0m"
                print(f"[{ts}] {c}{tag}{reset} {message}")

    def error(self, message, source="authprobe"):
        with _PRINT_LOCK:
            if self._managed:
                entry = {"ts": datetime.now().isoformat(), "source": source, "message": message}
                sys.stderr.write("__CRUCIBLE_ERR__:" + json.dumps(entry) + "\n")
                sys.stderr.flush()
            else:
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[{ts}] \033[31m[!]\033[0m {message}")

    def status(self, phase, label="", status="running", step="", progress=0, total=0):
        with _PRINT_LOCK:
            if self._managed:
                entry = {"phase": phase, "label": label, "status": status, "step": step,
                         "progress": progress, "total": total, "ts": datetime.now().isoformat()}
                sys.stdout.write("__CRUCIBLE_STATUS__:" + json.dumps(entry) + "\n")
                sys.stdout.flush()
            else:
                ts = datetime.now().strftime("%H:%M:%S")
                if step:
                    print(f"[{ts}] \033[36m[*]\033[0m [{label}] {step}")


_console = AuthProbeConsole()

# Suppress SSL warnings for testing
warnings.filterwarnings("ignore")

BANNER = r"""
   █████╗ ██╗   ██╗████████╗██╗  ██╗
  ██╔══██╗██║   ██║╚══██╔══╝██║  ██║
  ███████║██║   ██║   ██║   ███████║
  ██╔══██║██║   ██║   ██║   ██╔══██║
  ██║  ██║╚██████╔╝   ██║   ██║  ██║
  ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝

  ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
  ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
  ██████╔╝██████╔╝██║   ██║██████╔╝█████╗
  ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
  ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝

  Authentication Detection & Probing Tool  v{ver}
  For authorized security testing only
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
    "deviceToken", "devicetoken", "device_token",
    "refresh_token", "refreshToken",
    "csrfToken", "csrf_token",
    "api_token", "apiToken", "apiKey", "api_key",
    "userToken", "user_token",
    "x-auth-token", "x_auth_token",
}

# Top-level JSON keys that indicate a successful login user-profile response
_USER_PROFILE_KEYS = {
    "unique_id", "user_id", "userid",
    "permissions", "roles", "scopes", "groups",
    "login_time", "loginTime", "last_login",
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
    # Ubiquiti UniFi OS specific
    re.compile(r'"code"\s*:\s*"api\.err\.LoginMfaRequired"', re.I),
    re.compile(r'"msg"\s*:\s*"api\.err\.LoginMfaRequired"', re.I),
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
    # Ubiquiti UniFi Controller / UISP
    "/manage/account/login", "/nms/user/login", "/login.cgi",
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

# Well-known spec / discovery endpoint paths
_WELL_KNOWN_ENDPOINTS = [
    ("openid_configuration", "/.well-known/openid-configuration"),
    ("oauth_server",         "/.well-known/oauth-authorization-server"),
    ("openapi_json",         "/openapi.json"),
    ("swagger_json",         "/swagger.json"),
    ("swagger_v2",           "/swagger/v2/swagger.json"),
    ("api_docs",             "/api-docs"),
    ("v3_api_docs",          "/v3/api-docs"),
    ("graphql",              "/graphql"),
    ("graphql_playground",   "/playground"),
    ("auth_info",            "/auth-info"),
    ("wsdl",                 "/wsdl"),
    ("soap_endpoint",        "/soap"),
]

# URL path signals indicating API vs webapp
_API_URL_SIGNALS = [
    r"/api/v?\d+", r"/v\d+/", r"/rest/", r"/graphql", r"/gql",
    r"/swagger", r"/openapi", r"\.json$", r"/rpc/", r"/service/",
    r"/endpoint", r"/query", r"/_bulk", r"/_search", r"/oauth2/",
    r"/token", r"\.well-known/", r"/soap", r"/wsdl", r"\.wsdl$",
]

_WEBAPP_URL_SIGNALS = [
    r"/login", r"/signin", r"/auth/sign", r"/admin/", r"/dashboard",
    r"/portal", r"/user/", r"/account", r"/wp-login", r"/wp-admin",
]

# ─────────────────────────────────────────────────────────────
# Software fingerprint database
# ─────────────────────────────────────────────────────────────

SOFTWARE_FINGERPRINTS: list[dict] = [
    # ── CMS ───────────────────────────────────────────────────────────────────
    {
        "name": "WordPress",
        "url_type": "webapp",
        "auth_methods": ["form_login", "basic"],
        "indicators": {
            "url_patterns":  [r"/wp-login\.php", r"/wp-admin/", r"/wp-content/"],
            "html_patterns": [r'<input[^>]+id=["\']user_login["\']', r"wp-login\.php",
                              r'name=["\']log["\']', r'id=["\']loginform["\']'],
            "headers":       {"x-pingback": r"xmlrpc\.php", "link": r"wp-json"},
            "cookies":       [r"^wordpress_", r"^wp-settings-"],
            "body_keywords": ["wp-login", "WordPress", "wp-content/themes"],
        },
        "login_url_hint": "/wp-login.php",
        "login_username_field": "log",
        "login_password_field": "pwd",
    },
    {
        "name": "Joomla",
        "url_type": "webapp",
        "auth_methods": ["form_login"],
        "indicators": {
            "url_patterns":  [r"/administrator/", r"/index\.php\?option=com_"],
            "html_patterns": [r'name=["\']option["\'].*value=["\']com_login["\']',
                              r"Joomla!", r'id=["\']username["\'].*id=["\']password["\']'],
            "headers":       {},
            "cookies":       [r"^joomla_user_state"],
            "body_keywords": ["Joomla!", "com_users", "mod_login"],
        },
        "login_url_hint": "/administrator/index.php",
    },
    {
        "name": "Drupal",
        "url_type": "webapp",
        "auth_methods": ["form_login"],
        "indicators": {
            "url_patterns":  [r"/user/login", r"/sites/default/files/"],
            "html_patterns": [r'id=["\']user-login["\']',
                              r'name=["\']form_id["\'].*value=["\']user_login_form["\']',
                              r"Drupal\.settings", r"/sites/all/modules/"],
            "headers":       {"x-generator": r"Drupal"},
            "cookies":       [r"^SESS[0-9a-f]+$"],
            "body_keywords": ["Drupal", "sites/default", "drupal.js"],
        },
        "login_url_hint": "/user/login",
    },
    # ── DevOps / CI-CD ────────────────────────────────────────────────────────
    {
        "name": "Jenkins",
        "url_type": "webapp",
        "auth_methods": ["form_login", "basic", "token_login"],
        "indicators": {
            "url_patterns":  [r"/jenkins/", r"/j_acegi_security_check"],
            "html_patterns": [r'name=["\']j_username["\']', r'name=["\']j_password["\']',
                              r"Jenkins", r"j_spring_security_check",
                              r'id=["\']main-panel["\']'],
            "headers":       {"x-jenkins": r"\d+\.\d+"},
            "cookies":       [r"^JSESSIONID", r"^jenkins-remember-me"],
            "body_keywords": ["j_spring_security_check", "Jenkins", "hudson"],
        },
        "login_url_hint": "/j_spring_security_check",
        "login_username_field": "j_username",
        "login_password_field": "j_password",
    },
    {
        "name": "GitLab",
        "url_type": "webapp",
        "auth_methods": ["form_login", "bearer", "oauth2_client_creds", "saml_assertion"],
        "indicators": {
            "url_patterns":  [r"/gitlab/", r"/users/sign_in"],
            "html_patterns": [r'name=["\']authenticity_token["\']', r'GitLab',
                              r'class=["\']gl-', r'action=["\'][^"\']*sign_in["\']'],
            "headers":       {"x-gitlab-meta": None},
            "cookies":       [r"^_gitlab_session"],
            "body_keywords": ["GitLab", "gl-button", "gl-form", "authenticity_token"],
        },
        "login_url_hint": "/users/sign_in",
    },
    {
        "name": "Gitea",
        "url_type": "webapp",
        "auth_methods": ["form_login", "basic", "bearer"],
        "indicators": {
            "url_patterns":  [r"/gitea/"],
            "html_patterns": [r"Gitea", r'name=["\']_csrf["\']'],
            "headers":       {"x-gitea-object-format": None},
            "cookies":       [r"^i_like_gitea", r"^gitea_.*"],
            "body_keywords": ["Gitea", "i_like_gitea"],
        },
    },
    # ── Monitoring / Observability ─────────────────────────────────────────────
    {
        "name": "Grafana",
        "url_type": "webapp",
        "auth_methods": ["form_login", "basic", "bearer", "apikey_header",
                         "oauth2_client_creds", "saml_assertion"],
        "indicators": {
            "url_patterns":  [r"/grafana/", r"/login"],
            "html_patterns": [r"Grafana", r'ng-app=["\']grafana["\']',
                              r'class=["\']grafana-app["\']', r"GF_SESS"],
            "headers":       {"x-grafana-org-id": None},
            "cookies":       [r"^grafana_sess", r"^grafana_user", r"^GF_SESS"],
            "body_keywords": ["Grafana", "grafana-app", "GF_SESS", "grafanaBootData"],
        },
        "login_url_hint": "/login",
        "api_key_header_hint": "Authorization",
    },
    {
        "name": "Kibana",
        "url_type": "webapp",
        "auth_methods": ["form_login", "basic", "apikey_header", "bearer"],
        "indicators": {
            "url_patterns":  [r"/kibana/"],
            "html_patterns": [r"Kibana", r'kbn-xsrf', r"kbnBootstrap"],
            "headers":       {"kbn-name": r"kibana"},
            "cookies":       [r"^sid="],
            "body_keywords": ["kibana", "kbnBootstrap", "kbn-xsrf"],
        },
        "api_key_header_hint": "Authorization",
    },
    {
        "name": "Prometheus",
        "url_type": "api",
        "auth_methods": ["basic", "bearer"],
        "indicators": {
            "url_patterns":  [r"/prometheus/", r"/metrics", r"/api/v1/query"],
            "html_patterns": [r"Prometheus Time Series", r"/api/v1/"],
            "headers":       {},
            "cookies":       [],
            "body_keywords": ["Prometheus", "promhttp", "tsdb"],
        },
    },
    # ── Identity / SSO ────────────────────────────────────────────────────────
    {
        "name": "Okta",
        "url_type": "webapp",
        "auth_methods": ["form_login", "oauth2_client_creds", "oidc_token", "saml_assertion"],
        "indicators": {
            "url_patterns":  [r"\.okta\.com", r"/okta/"],
            "html_patterns": [r"okta-signin", r'id=["\']okta-sign-in["\']', r"OktaUtil"],
            "headers":       {},
            "cookies":       [r"^sid=", r"^oktaStateToken"],
            "body_keywords": ["okta-signin", "OktaUtil", "okta.com"],
        },
    },
    {
        "name": "Keycloak",
        "url_type": "webapp",
        "auth_methods": ["form_login", "oauth2_client_creds", "oidc_token", "saml_assertion"],
        "indicators": {
            "url_patterns":  [r"/realms/[^/]+/protocol/", r"/auth/realms/"],
            "html_patterns": [r"Keycloak", r"kc-form-login", r'id=["\']kc-login["\']'],
            "headers":       {},
            "cookies":       [r"^KEYCLOAK_SESSION", r"^AUTH_SESSION_ID"],
            "body_keywords": ["Keycloak", "kc-form", "keycloak-admin"],
        },
    },
    {
        "name": "ADFS",
        "url_type": "webapp",
        "auth_methods": ["form_login", "kerberos", "ntlm", "saml_assertion"],
        "indicators": {
            "url_patterns":  [r"/adfs/ls/", r"/adfs/oauth2/", r"/FederationMetadata/"],
            "html_patterns": [r"Active Directory Federation Services",
                              r"MSISAuth", r'name=["\']AuthMethod["\']'],
            "headers":       {},
            "cookies":       [r"^MSISAuth", r"^MSISAuthenticated"],
            "body_keywords": ["ADFS", "Active Directory Federation", "MSISAuth"],
        },
    },
    {
        "name": "Azure AD / Entra ID",
        "url_type": "webapp",
        "auth_methods": ["oauth2_client_creds", "oidc_token", "saml_assertion", "kerberos"],
        "indicators": {
            "url_patterns":  [r"login\.microsoftonline\.com", r"login\.microsoft\.com",
                              r"microsoftonline\.com/oauth2"],
            "html_patterns": [r"Microsoft.*Sign in", r'id=["\']i0116["\']',
                              r"convergedlogin", r"login\.microsoftonline"],
            "headers":       {"x-ms-request-id": None, "x-ms-ests-server": None},
            "cookies":       [r"^x-ms-gateway-slice", r"^ESTSAUTH"],
            "body_keywords": ["microsoftonline", "login.microsoft", "convergedlogin"],
        },
    },
    {
        "name": "Google OAuth",
        "url_type": "webapp",
        "auth_methods": ["oauth2_client_creds", "oidc_token"],
        "indicators": {
            "url_patterns":  [r"accounts\.google\.com", r"oauth2\.googleapis\.com"],
            "html_patterns": [r"Google Sign-In", r'name=["\']Passwd["\']'],
            "headers":       {},
            "cookies":       [r"^GAPS=", r"^GALX="],
            "body_keywords": ["accounts.google.com", "google-sign-in"],
        },
    },
    # ── Firewalls / Network Appliances ────────────────────────────────────────
    {
        "name": "Palo Alto PAN-OS",
        "url_type": "webapp",
        "auth_methods": ["form_login", "apikey_header", "basic"],
        "indicators": {
            "url_patterns":  [r"/php/login\.php", r"/api/\?type=keygen"],
            "html_patterns": [r"PAN-OS", r"PaloAlto",
                              r'id=["\']user["\'].*id=["\']passwd["\']'],
            "headers":       {"x-pan-authcheck": None},
            "cookies":       [r"^PHPSESSID", r"^PAN"],
            "body_keywords": ["PAN-OS", "PaloAlto", "panui"],
        },
        "api_key_header_hint": "X-PAN-KEY",
    },
    {
        "name": "Fortinet FortiGate",
        "url_type": "webapp",
        "auth_methods": ["form_login", "apikey_header", "bearer"],
        "indicators": {
            "url_patterns":  [r"/logincheck", r"/remote/login"],
            "html_patterns": [r"FortiGate", r"Fortinet", r"APSCOOKIE"],
            "headers":       {"set-cookie": r"APSCOOKIE"},
            "cookies":       [r"^APSCOOKIE_", r"^SVPNCOOKIE"],
            "body_keywords": ["FortiGate", "Fortinet", "APSCOOKIE"],
        },
    },
    {
        "name": "Cisco ASA",
        "url_type": "webapp",
        "auth_methods": ["form_login", "basic"],
        "indicators": {
            "url_patterns":  [r"/\+CSCOE\+/logon\.html", r"/webvpn\.html"],
            "html_patterns": [r"Cisco Adaptive Security", r"CSCOE", r"webvpn"],
            "headers":       {"server": r"Cisco"},
            "cookies":       [r"^webvpn"],
            "body_keywords": ["Cisco ASA", "CSCOE", "webvpn"],
        },
    },
    {
        "name": "F5 BIG-IP",
        "url_type": "webapp",
        "auth_methods": ["form_login", "bearer", "kerberos"],
        "indicators": {
            "url_patterns":  [r"/my\.policy", r"/tmui/login\.jsp", r"/iControl/"],
            "html_patterns": [r"BIG-IP", r"F5 Networks", r'id=["\']MRHSession["\']'],
            "headers":       {"server": r"BigIP"},
            "cookies":       [r"^MRHSession", r"^BIGipServer"],
            "body_keywords": ["BIG-IP", "F5 Networks", "MRHSession"],
        },
    },
    {
        "name": "Check Point",
        "url_type": "webapp",
        "auth_methods": ["form_login", "bearer"],
        "indicators": {
            "url_patterns":  [r"/cgi-bin/login", r"/sslvpn/Login/Login"],
            "html_patterns": [r"Check Point", r"cprops"],
            "headers":       {"server": r"Check.Point"},
            "cookies":       [r"^CPCVS=", r"^cp_sess="],
            "body_keywords": ["Check Point", "cprops"],
        },
    },
    # ── Virtualization / Infrastructure ───────────────────────────────────────
    {
        "name": "Proxmox VE",
        "url_type": "webapp",
        "auth_methods": ["form_login", "apikey_header", "token_login"],
        "indicators": {
            "url_patterns":  [r"/pve2/", r":8006"],
            "html_patterns": [r"Proxmox", r'name=["\']PVEAuthCookie["\']', r"pvemanager"],
            "headers":       {},
            "cookies":       [r"^PVEAuthCookie"],
            "body_keywords": ["Proxmox", "PVEAuthCookie", "pvemanager"],
        },
        "api_key_header_hint": "Authorization",
    },
    {
        "name": "VMware vSphere / ESXi",
        "url_type": "webapp",
        "auth_methods": ["form_login", "basic", "saml_assertion"],
        "indicators": {
            "url_patterns":  [r"/vsphere-client/", r"/ui/", r"/sdk"],
            "html_patterns": [r"VMware vSphere", r"vCenter", r"ESXi", r"vmware-main"],
            "headers":       {"server": r"VMware"},
            "cookies":       [r"^vmware_client", r"^VSPHERE-UI-JSESSIONID"],
            "body_keywords": ["VMware", "vCenter", "vSphere", "ESXi"],
        },
    },
    # ── ITSM / Ticketing ─────────────────────────────────────────────────────
    {
        "name": "ServiceNow",
        "url_type": "webapp",
        "auth_methods": ["form_login", "basic", "bearer", "oauth2_client_creds",
                         "saml_assertion"],
        "indicators": {
            "url_patterns":  [r"\.service-now\.com", r"/servicenow/"],
            "html_patterns": [r"ServiceNow", r'name=["\']glide_user["\']', r"g_ck"],
            "headers":       {},
            "cookies":       [r"^glide_user", r"^glide_session_store"],
            "body_keywords": ["ServiceNow", "glide_user", "g_ck", "service-now.com"],
        },
    },
    {
        "name": "Atlassian Jira / Confluence",
        "url_type": "webapp",
        "auth_methods": ["form_login", "basic", "bearer", "oauth2_client_creds"],
        "indicators": {
            "url_patterns":  [r"/jira/", r"/confluence/", r"/secure/Dashboard\.jspa"],
            "html_patterns": [r"Jira", r"Confluence", r"Atlassian",
                              r'name=["\']atl\.xsrf\.token["\']', r"atlassian"],
            "headers":       {"x-ajs-user-key": None, "x-seraph-loginreason": None},
            "cookies":       [r"^JSESSIONID", r"^seraph"],
            "body_keywords": ["Atlassian", "atlassian", "atl.xsrf.token"],
        },
    },
    # ── API Gateways / Management ─────────────────────────────────────────────
    {
        "name": "Kong API Gateway",
        "url_type": "api",
        "auth_methods": ["bearer", "apikey_header", "oauth2_client_creds", "basic"],
        "indicators": {
            "url_patterns":  [r"/kong/", r"/__admin/"],
            "html_patterns": [],
            "headers":       {"server": r"kong", "x-kong-proxy-latency": None,
                              "x-kong-upstream-latency": None},
            "cookies":       [],
            "body_keywords": [],
        },
        "api_key_header_hint": "apikey",
    },
    {
        "name": "AWS API Gateway",
        "url_type": "api",
        "auth_methods": ["apikey_header", "bearer", "aws_sigv4"],
        "indicators": {
            "url_patterns":  [r"\.execute-api\.[^.]+\.amazonaws\.com",
                              r"\.apigateway\.amazonaws\.com"],
            "html_patterns": [],
            "headers":       {"x-amzn-requestid": None, "x-amz-cf-id": None},
            "cookies":       [],
            "body_keywords": [],
        },
        "api_key_header_hint": "x-api-key",
    },
    {
        "name": "Azure API Management",
        "url_type": "api",
        "auth_methods": ["apikey_header", "bearer", "oauth2_client_creds"],
        "indicators": {
            "url_patterns":  [r"\.azure-api\.net", r"\.management\.azure\.com"],
            "html_patterns": [],
            "headers":       {"ocp-apim-subscription-key": None,
                              "ocp-apim-trace-id": None},
            "cookies":       [],
            "body_keywords": [],
        },
        "api_key_header_hint": "Ocp-Apim-Subscription-Key",
    },
    {
        "name": "Apigee API Gateway",
        "url_type": "api",
        "auth_methods": ["apikey_header", "bearer", "oauth2_client_creds"],
        "indicators": {
            "url_patterns":  [r"\.apigee\.net", r"\.apigee\.com"],
            "html_patterns": [],
            "headers":       {"x-apigee-fault-code": None, "x-request-id": None},
            "cookies":       [],
            "body_keywords": ["apigee", "fault-code"],
        },
        "api_key_header_hint": "x-api-key",
    },
    # ── Kubernetes / Container ─────────────────────────────────────────────────
    {
        "name": "Kubernetes API Server",
        "url_type": "api",
        "auth_methods": ["bearer", "mtls", "basic"],
        "indicators": {
            "url_patterns":  [r"/api/v\d+/", r"/apis/apps/v\d+/"],
            "html_patterns": [],
            "headers":       {},
            "cookies":       [],
            "body_keywords": ['"apiVersion"', '"kind"', '"metadata"', "kubernetes"],
            "json_keys":     ["apiVersion", "kind", "items", "metadata"],
        },
    },
    {
        "name": "Docker Registry",
        "url_type": "api",
        "auth_methods": ["basic", "bearer", "token_login"],
        "indicators": {
            "url_patterns":  [r"/v2/"],
            "html_patterns": [],
            "headers":       {"www-authenticate": r"Bearer realm=",
                              "docker-distribution-api-version": r"registry/2\.0"},
            "cookies":       [],
            "body_keywords": [],
        },
    },
    # ── Databases / Storage Web UIs ────────────────────────────────────────────
    {
        "name": "phpMyAdmin",
        "url_type": "webapp",
        "auth_methods": ["form_login"],
        "indicators": {
            "url_patterns":  [r"/phpmyadmin/", r"/pma/"],
            "html_patterns": [r"phpMyAdmin", r'name=["\']pma_username["\']'],
            "headers":       {},
            "cookies":       [r"^phpMyAdmin"],
            "body_keywords": ["phpMyAdmin", "pma_username", "pma_password"],
        },
        "login_username_field": "pma_username",
        "login_password_field": "pma_password",
    },
    {
        "name": "Elasticsearch / OpenSearch",
        "url_type": "api",
        "auth_methods": ["basic", "bearer", "apikey_header"],
        "indicators": {
            "url_patterns":  [r"/_cat/", r"/_cluster/health", r"/_nodes"],
            "html_patterns": [],
            "headers":       {"x-elastic-product": None},
            "cookies":       [],
            "body_keywords": ["cluster_name", "tagline", "You Know, for Search"],
            "json_keys":     ["cluster_name", "status", "number_of_nodes"],
        },
    },
    # ── Web Frameworks / Generic Patterns ─────────────────────────────────────
    {
        "name": "Django / Python Web App",
        "url_type": "webapp",
        "auth_methods": ["form_login", "bearer", "session_cookie"],
        "indicators": {
            "url_patterns":  [r"/admin/login/", r"/accounts/login/"],
            "html_patterns": [r'name=["\']csrfmiddlewaretoken["\']',
                              r"csrfmiddlewaretoken"],
            "headers":       {},
            "cookies":       [r"^csrftoken", r"^sessionid"],
            "body_keywords": ["csrfmiddlewaretoken", "django"],
        },
    },
    {
        "name": "Laravel / PHP Framework",
        "url_type": "webapp",
        "auth_methods": ["form_login", "bearer", "apikey_header"],
        "indicators": {
            "url_patterns":  [r"/login"],
            "html_patterns": [r'name=["\']_token["\']', r"Laravel", r"laravel"],
            "headers":       {"set-cookie": r"laravel_session"},
            "cookies":       [r"^laravel_session", r"^XSRF-TOKEN"],
            "body_keywords": ["laravel", "_token", "XSRF-TOKEN"],
        },
    },
    {
        "name": "Ruby on Rails",
        "url_type": "webapp",
        "auth_methods": ["form_login", "bearer"],
        "indicators": {
            "url_patterns":  [],
            "html_patterns": [r'name=["\']authenticity_token["\']', r'csrf-token',
                              r'meta.*name=["\']csrf-token["\']'],
            "headers":       {"x-csrf-token": None},
            "cookies":       [r"^_session_id", r"^_.*_session"],
            "body_keywords": ["authenticity_token", "rails"],
        },
    },
    {
        "name": "Spring Boot / Java",
        "url_type": "webapp",
        "auth_methods": ["form_login", "basic", "bearer", "oauth2_client_creds"],
        "indicators": {
            "url_patterns":  [r"/actuator/", r"/swagger-ui/", r"/v3/api-docs"],
            "html_patterns": [r'name=["\']_csrf["\']', r"Spring",
                              r"Whitelabel Error Page"],
            "headers":       {"x-application-context": None},
            "cookies":       [r"^JSESSIONID"],
            "body_keywords": ["Whitelabel Error Page", "Spring Boot", "actuator"],
        },
    },
    {
        "name": "ASP.NET / .NET Web App",
        "url_type": "webapp",
        "auth_methods": ["form_login", "ntlm", "kerberos", "bearer"],
        "indicators": {
            "url_patterns":  [r"\.aspx", r"/Account/Login", r"/__RequestVerificationToken"],
            "html_patterns": [r'name=["\']__RequestVerificationToken["\']',
                              r"ASP\.NET", r"__VIEWSTATE"],
            "headers":       {"x-aspnet-version": None, "x-powered-by": r"ASP\.NET"},
            "cookies":       [r"^ASP\.NET_SessionId", r"^\.ASPXAUTH",
                              r"^__RequestVerificationToken"],
            "body_keywords": ["__RequestVerificationToken", "ASP.NET", "__VIEWSTATE"],
        },
    },
    # ── Ubiquiti Network Hardware ─────────────────────────────────────────────
    {
        "name": "Ubiquiti UniFi OS",
        "url_type": "webapp",
        "auth_methods": ["token_login", "totp_mfa"],
        "indicators": {
            "url_patterns":  [],
            "html_patterns": [r"<title>\s*UniFi\s*OS\s*</title>",
                              r"/manage/static/",
                              r"window\.__ubnt\s*=",
                              r'<link[^>]+href=["\'][^"\']*manage[^"\']*favicon'],
            "headers":       {"x-csrf-token": None},
            "cookies":       [r"^TOKEN$"],
            "body_keywords": ["UniFi OS", "window.__ubnt", "/manage/static/"],
        },
        "login_url_hint": "/api/auth/login",
        "login_username_field": "username",
        "login_password_field": "password",
    },
    {
        "name": "Ubiquiti UniFi Network Controller",
        "url_type": "webapp",
        "auth_methods": ["token_login", "totp_mfa"],
        "indicators": {
            "url_patterns":  [r":8443", r"/manage/"],
            "html_patterns": [r'ng-app=["\']unifi["\']',
                              r"<title>\s*UniFi\s*</title>",
                              r"angular.*unifi|unifi.*angular",
                              r"unifi-manage\.js"],
            "headers":       {},
            "cookies":       [r"^unifises", r"^csrf_token"],
            "body_keywords": ["unifises", "ng-app=\"unifi\"", "unifi-manage"],
        },
        "login_url_hint": "/api/login",
        "login_username_field": "username",
        "login_password_field": "password",
    },
    {
        "name": "Ubiquiti AirOS",
        "url_type": "webapp",
        "auth_methods": ["form_login"],
        "indicators": {
            "url_patterns":  [r"/airmax/"],
            "html_patterns": [r"AirOS", r"airOS", r"ubnt.*(?:login|auth)",
                              r"<title>\s*(?:airOS|AirOS)"],
            "headers":       {"server": r"(?:lighttpd|AirOS|ubnt)"},
            "cookies":       [r"^AIROS_SESSIONID"],
            "body_keywords": ["AirOS", "airOS", "UBNT"],
        },
        "login_url_hint": "/login.cgi",
        "login_username_field": "username",
        "login_password_field": "password",
    },
    {
        "name": "Ubiquiti UISP",
        "url_type": "webapp",
        "auth_methods": ["token_login", "totp_mfa"],
        "indicators": {
            "url_patterns":  [r"/nms/"],
            "html_patterns": [r"<title>\s*UISP\s*</title>", r"uisp", r"UISP",
                              r"/nms/static/"],
            "headers":       {},
            "cookies":       [r"^x-auth-token"],
            "body_keywords": ["UISP", "uisp", "/nms/static/"],
        },
        "login_url_hint": "/nms/user/login",
        "login_username_field": "email",
        "login_password_field": "password",
    },
    {
        "name": "Ubiquiti EdgeOS",
        "url_type": "webapp",
        "auth_methods": ["form_login", "token_login"],
        "indicators": {
            "url_patterns":  [],
            "html_patterns": [r"<title>\s*EdgeOS\s*</title>", r"EdgeOS",
                              r"edgeos", r"vyatta"],
            "headers":       {"set-cookie": r"PHPSESSID"},
            "cookies":       [r"^PHPSESSID"],
            "body_keywords": ["EdgeOS", "edgerouter", "vyatta"],
        },
        "login_url_hint": "/",
        "login_username_field": "username",
        "login_password_field": "password",
    },
]


# ─────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────

def _make_session(args):
    try:
        import requests
        from requests.adapters import HTTPAdapter
    except ImportError:
        _console.error("requests library not installed. Run: pip install requests")
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


def _make_session_raw(proxy: str = "", timeout: int = 10):
    """Create session without an args object (for programmatic use)."""
    try:
        import requests
        from requests.adapters import HTTPAdapter
    except ImportError:
        return None
    sess = requests.Session()
    sess.verify = False
    sess.headers.update({
        "User-Agent": f"AuthProbe/{VERSION} (Security Assessment)",
        "Accept": "application/json, text/html, */*",
    })
    if proxy:
        sess.proxies = {"http": proxy, "https": proxy}
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
    """Return (cookie_name, cookie_value) from an MFA challenge response."""
    _mfa_keys = ("mfaCookie", "mfa_cookie", "mfa_token", "challengeCookie")
    _sources: list = [body or {}]
    if isinstance((body or {}).get("data"), dict):
        _sources.append(body["data"])

    for src in _sources:
        for key in _mfa_keys:
            val = src.get(key, "")
            if val and isinstance(val, str):
                if "=" in val and not val.startswith("eyJ"):
                    name, _, value = val.partition("=")
                    return name.strip(), value.strip()
                return key, val

    if resp is not None:
        for raw in resp.headers.get("Set-Cookie", "").split(","):
            part = raw.strip().split(";")[0]
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
    parent = "/".join(login_path.split("/")[:-1]) or "/"
    seen: set = set()
    paths: list = []

    def _add(p: str) -> None:
        p = p.rstrip("/") or "/"
        if p not in seen:
            seen.add(p)
            paths.append(p)

    for sfx in _MFA_SUBMISSION_SUFFIXES:
        _add(parent + sfx)
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
    """Attempt to complete a TOTP MFA challenge."""
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
# Software fingerprinting
# ─────────────────────────────────────────────────────────────

def fingerprint_software(
    url: str,
    headers: dict,
    body: str,
    cookie_names: list,
) -> list[dict]:
    """Match against SOFTWARE_FINGERPRINTS; return confidence-scored list."""
    results: list[dict] = []
    h_lower   = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body.lower()

    for fp in SOFTWARE_FINGERPRINTS:
        score   = 0
        signals = []
        ind     = fp.get("indicators", {})

        for pat in ind.get("url_patterns", []):
            if re.search(pat, url, re.IGNORECASE):
                score += 30
                signals.append(f"URL matches {pat!r}")

        for pat in ind.get("html_patterns", []):
            if re.search(pat, body, re.IGNORECASE):
                score += 20
                signals.append(f"Body matches {pat!r}")

        for hdr, pat in ind.get("headers", {}).items():
            val = h_lower.get(hdr.lower(), "")
            if val:
                if pat is None or re.search(pat, val, re.IGNORECASE):
                    score += 25
                    signals.append(f"Header {hdr!r}: {val[:60]!r}")

        for cpat in ind.get("cookies", []):
            for cname in cookie_names:
                if re.search(cpat, cname, re.IGNORECASE):
                    score += 25
                    signals.append(f"Cookie matches {cpat!r}: {cname!r}")

        for kw in ind.get("body_keywords", []):
            if kw.lower() in body_lower:
                score += 10
                signals.append(f"Body keyword: {kw!r}")

        if score >= 20:
            results.append({
                "name":               fp["name"],
                "url_type":           fp.get("url_type", "unknown"),
                "confidence":         min(score, 100),
                "indicators":         signals,
                "auth_hints":         fp.get("auth_methods", []),
                "login_url_hint":     fp.get("login_url_hint", ""),
                "login_username_field": fp.get("login_username_field", ""),
                "login_password_field": fp.get("login_password_field", ""),
                "api_key_header_hint": fp.get("api_key_header_hint", ""),
            })

    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results


# ─────────────────────────────────────────────────────────────
# Rendered-page fingerprinting (Selenium)
# ─────────────────────────────────────────────────────────────

# JS globals to probe for known frameworks / platforms
_JS_GLOBALS_SIGNALS = [
    ("window.__ubnt",       "Ubiquiti: window.__ubnt global detected"),
    ("window.ubnt",         "Ubiquiti: window.ubnt global detected"),
    ("window.unifi",        "Ubiquiti: window.unifi global detected"),
    ("window.UniFiOS",      "Ubiquiti: window.UniFiOS global detected"),
    ("window.angular",      "Angular framework detected"),
    ("window.React",        "React framework detected"),
    ("window.ReactDOM",     "React (DOM) framework detected"),
    ("window.Vue",          "Vue.js framework detected"),
    ("window.grafana",      "Grafana: window.grafana global detected"),
    ("window.GF_USER",      "Grafana: GF_USER global detected"),
    ("window.GF_SESS",      "Grafana: GF_SESS global detected"),
    ("window.Keycloak",     "Keycloak: window.Keycloak global detected"),
    ("window.OktaUtil",     "Okta: window.OktaUtil global detected"),
]


def fingerprint_rendered(
    url: str,
    timeout: int = 15,
    proxy: str = "",
    driver_path: str = "",
) -> dict:
    """
    Render *url* in a headless Chrome browser and extract fingerprint signals
    from the JavaScript-rendered DOM.

    Returns::

        {
          "title":            str,
          "visible_text":     str,
          "rendered_html":    str (first 20 000 chars),
          "software_matches": list,   # same schema as fingerprint_software()
          "dom_signals":      list[str],
          "rendered_cookies": list[str],
          "error":            str,    # non-empty on failure
        }

    Returns {"error": "..."} immediately when Selenium is not installed.
    """
    _console.log(f"[rendered] Starting headless Chrome render of {url}...", "INFO")
    result: dict = {
        "title":            "",
        "visible_text":     "",
        "rendered_html":    "",
        "software_matches": [],
        "dom_signals":      [],
        "rendered_cookies": [],
        "error":            "",
    }
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from selenium.common.exceptions import (
            WebDriverException,
            TimeoutException as _SeleniumTimeout,
        )
    except ImportError:
        result["error"] = "selenium not available (pip install selenium)"
        return result

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--allow-insecure-localhost")
    opts.add_argument(f"--user-agent=AuthProbe/{VERSION} (Security Assessment)")
    if proxy:
        opts.add_argument(f"--proxy-server={proxy}")
    # Suppress DevTools noise
    opts.add_experimental_option("excludeSwitches", ["enable-logging"])

    driver = None
    try:
        svc_kwargs: dict = {}
        if driver_path:
            svc_kwargs["executable_path"] = driver_path
        try:
            svc = Service(**svc_kwargs) if svc_kwargs else Service()
            driver = webdriver.Chrome(service=svc, options=opts)
        except WebDriverException as exc:
            result["error"] = f"ChromeDriver init failed: {exc}"
            return result

        driver.set_page_load_timeout(timeout)
        try:
            driver.get(url)
        except _SeleniumTimeout:
            # Partial load may still yield useful signals
            pass
        except WebDriverException as exc:
            result["error"] = f"Page load failed: {exc}"
            return result

        # Brief wait for JS to execute and render initial content
        import time as _time
        _time.sleep(min(3, timeout // 4))

        result["title"] = driver.title or ""

        try:
            result["visible_text"] = (
                driver.execute_script("return document.body ? document.body.innerText : '';")
                or ""
            )
        except Exception:
            pass

        try:
            result["rendered_html"] = driver.page_source[:20000]
        except Exception:
            pass

        # Collect browser-set cookies
        try:
            result["rendered_cookies"] = [c["name"] for c in driver.get_cookies()]
        except Exception:
            pass

        # Probe JS-level globals
        dom_signals: list = []
        for js_expr, signal in _JS_GLOBALS_SIGNALS:
            try:
                present = driver.execute_script(
                    f"return typeof {js_expr} !== 'undefined';"
                )
                if present:
                    dom_signals.append(signal)
            except Exception:
                pass

        # Detect rendered <input type="password"> (SPAs render these dynamically)
        try:
            pw_inputs = driver.execute_script(
                "return document.querySelectorAll('input[type=\"password\"]').length;"
            )
            if pw_inputs:
                dom_signals.append(
                    f"Rendered DOM: {pw_inputs} password input(s) found after JS execution"
                )
        except Exception:
            pass

        result["dom_signals"] = dom_signals

        # Re-run static fingerprinting on the rendered HTML + title + visible text
        combined_body = (
            result["rendered_html"]
            + "\n" + result["title"]
            + "\n" + result["visible_text"]
        )
        sw_matches = fingerprint_software(
            url, {}, combined_body, result["rendered_cookies"]
        )
        result["software_matches"] = sw_matches

    except Exception as exc:
        result["error"] = f"Rendering error: {exc}"
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

    return result


# ─────────────────────────────────────────────────────────────
# Well-known / spec endpoint discovery
# ─────────────────────────────────────────────────────────────

def probe_well_known(sess, base_url: str, timeout: int) -> dict:
    """Probe well-known spec/discovery endpoints from origin root."""
    _console.log(f"[well-known] Probing {len(_WELL_KNOWN_ENDPOINTS)} spec endpoints...", "INFO")
    parsed = urlparse(base_url)
    port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    origin = f"{parsed.scheme}://{parsed.hostname}{port_part}"

    found = {}
    for key, path in _WELL_KNOWN_ENDPOINTS:
        probe_url = origin.rstrip("/") + path
        r = _safe_get(sess, probe_url, max(5, timeout // 2))
        if r is not None and r.status_code in (200, 401, 403):
            ct = r.headers.get("content-type", "")
            body_snip = ""
            try:
                body_snip = r.text[:300]
            except Exception:
                pass
            found[key] = {
                "url":            probe_url,
                "status_code":    r.status_code,
                "is_json":        "json" in ct.lower(),
                "body_snip":      body_snip,
                "www_authenticate": r.headers.get("WWW-Authenticate", ""),
            }
    return found


# ─────────────────────────────────────────────────────────────
# URL type classification
# ─────────────────────────────────────────────────────────────

def classify_url_type(
    url: str,
    resp,
    body: str,
    well_known: dict,
    software_matches: list,
) -> tuple[str, int]:
    """Return (url_type, confidence 0-100)."""
    api_score = 0
    web_score = 0

    ct = (resp.headers.get("content-type", "") if resp is not None else "").lower()
    if "json" in ct or "xml" in ct:
        api_score += 30
    elif "html" in ct:
        web_score += 30
    elif "text/plain" in ct:
        api_score += 10

    for pat in _API_URL_SIGNALS:
        if re.search(pat, url, re.IGNORECASE):
            api_score += 15
    for pat in _WEBAPP_URL_SIGNALS:
        if re.search(pat, url, re.IGNORECASE):
            web_score += 15

    if "openid_configuration" in well_known:
        api_score += 25
    if any(k in well_known for k in ("openapi_json", "swagger_json", "v3_api_docs")):
        api_score += 30
    if "graphql" in well_known and well_known["graphql"]["status_code"] in (200, 400):
        api_score += 30
    if "wsdl" in well_known and well_known["wsdl"]["status_code"] == 200:
        api_score += 35
    if "soap_endpoint" in well_known and well_known["soap_endpoint"]["status_code"] in (200, 400, 405, 500):
        api_score += 20

    if body:
        if re.search(r'<html[\s>]', body, re.IGNORECASE):
            web_score += 20
        if re.search(r'<input[^>]+type=["\']?password', body, re.IGNORECASE):
            web_score += 20
        stripped = body.strip()
        if stripped.startswith(("{", "[")):
            api_score += 20
        if re.search(r'"openapi"\s*:|"swagger"\s*:', body, re.IGNORECASE):
            api_score += 30
        if re.search(r'"apiVersion"\s*:', body):
            api_score += 20
        if re.search(r'xmlns.*soap|soapenv:|<wsdl:|<definitions\s', body, re.IGNORECASE):
            api_score += 30

    for sw in software_matches[:2]:
        sw_type = sw.get("url_type", "")
        if sw_type == "api":
            api_score += 20 * sw["confidence"] // 100
        elif sw_type == "webapp":
            web_score += 20 * sw["confidence"] // 100

    if resp is not None and resp.status_code == 401:
        api_score += 10

    total = max(api_score + web_score, 1)
    if api_score > web_score * 1.5:
        url_type = "api"
        conf = min(int(api_score * 100 // total), 95)
    elif web_score > api_score * 1.5:
        url_type = "webapp"
        conf = min(int(web_score * 100 // total), 95)
    elif api_score > 0 and web_score > 0:
        url_type = "hybrid"
        conf = 50
    else:
        url_type = "unknown"
        conf = 10

    return url_type, conf


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
    """Detect JSON API authentication by inspecting the response body and status."""
    if resp is None:
        return
    if not _is_json_response(resp) and resp.status_code not in (400, 401, 403, 422):
        return

    body_text = resp.text or ""
    body_json  = _json_body(resp)

    if resp.status_code in (401, 403) and (body_json or body_text.strip().startswith("{")):
        findings["json_api_auth"] = True
        findings["json_api_auth_url"] = url
        for pat in _JSON_CRED_FAILURE_PATTERNS:
            if pat.search(body_text):
                findings["json_api_cred_checked"] = True
                break
        return

    for pat in _JSON_AUTH_ERROR_PATTERNS:
        if pat.search(body_text):
            findings["json_api_auth"] = True
            findings["json_api_auth_url"] = url
            break

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


_APIKEY_COOKIE_NAMES = re.compile(
    r'^(api[_-]?key|x[_-]?api[_-]?key|auth[_-]?key|access[_-]?key|app[_-]?key|'
    r'client[_-]?key|secret[_-]?key|private[_-]?key|apitoken|api[_-]?token)$',
    re.I,
)


def detect_apikey_cookie(resp, findings: dict):
    """Detect API-key-in-cookie auth by inspecting Set-Cookie headers."""
    if resp is None:
        return
    for cookie in resp.cookies:
        if _APIKEY_COOKIE_NAMES.match(cookie.name):
            findings["apikey_cookie_hints"].append(cookie.name)


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
    _console.log(f"[login-discovery] Probing {len(_LOGIN_PROBE_PATHS)} common login paths against {origin}...", "INFO")
    found = []
    for path in _LOGIN_PROBE_PATHS:
        if path.rstrip("/") in skip_paths:
            continue
        url = origin.rstrip("/") + path
        r = _safe_get(sess, url, timeout)
        # Many API login endpoints are POST-only; if GET returns 404/405 try POST
        if r is None or r.status_code in (404, 405):
            r = _safe_post(sess, url, timeout,
                           json={},
                           headers={"Content-Type": "application/json",
                                    "Accept": "application/json"})
        if r is not None and r.status_code in (200, 301, 302, 400, 401, 403, 405, 422):
            ct = r.headers.get("Content-Type", "").lower()
            if probe_type == "api" and r.status_code == 200 and "text/html" in ct:
                continue
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
        _console.log(f"[login-discovery] Found {len(found)} login endpoint(s)", "SUCCESS")
        existing = {ep["path"] for ep in findings.get("login_endpoints", [])}
        for ep in found:
            if ep["path"] not in existing:
                findings["login_endpoints"].append(ep)
    else:
        _console.log("[login-discovery] No additional login endpoints found", "INFO")


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


def validate_apikey_cookie(sess, url: str, api_key: str,
                          cookie_name: str, timeout: int) -> dict:
    import copy
    import requests
    s2 = copy.copy(sess)
    s2.cookies = requests.cookies.RequestsCookieJar()
    s2.cookies.update(sess.cookies)
    s2.cookies.set(cookie_name, api_key)
    r = _safe_get(s2, url, timeout)
    ok = r is not None and r.status_code not in (401, 403)
    return {"method": "apikey_cookie", "success": ok,
            "status": r.status_code if r else None,
            "evidence": f"cookie {cookie_name}=<key>"}


def validate_apikey_header(sess, url: str, api_key: str,
                           header_name: str, timeout: int) -> dict:
    import copy
    s2 = copy.copy(sess)
    s2.headers = dict(sess.headers)
    s2.headers[header_name] = api_key
    r = _safe_get(s2, url, timeout)
    ok = r is not None and r.status_code not in (401, 403)
    return {"method": "apikey_header", "success": ok,
            "status": r.status_code if r else None,
            "evidence": f"header {header_name}: <key>"}


def validate_token_login(sess, login_url: str, username: str, password: str,
                         timeout: int) -> dict:
    """POST JSON credentials to a login endpoint; check for token in response."""
    _console.log(f"[validate] Testing token login against {login_url}...", "INFO")
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

        if _is_mfa_challenge(r, body_text):
            mfa_types = _extract_mfa_types(body) if isinstance(body, dict) else []
            cookie_name, cookie_value = _extract_mfa_cookie(body, r)
            totp_id = _extract_default_totp_id(body)
            best.update({
                "success":               True,
                "mfa_required":          True,
                "mfa_types":             mfa_types,
                "mfa_cookie_name":       cookie_name,
                "mfa_cookie_value":      cookie_value,
                "totp_authenticator_id": totp_id,
                "evidence":      (
                    f"Credentials accepted — MFA challenge issued "
                    f"(HTTP {r.status_code}, field combo: {ufield}/{pfield})"
                    + (f". MFA types: {', '.join(mfa_types)}" if mfa_types else "")
                ),
                "field_combo":   f"{ufield}/{pfield}",
            })
            return best

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
            top_keys = {k.lower() for k in body.keys()}
            profile_hits = top_keys & _USER_PROFILE_KEYS
            if len(profile_hits) >= 2:
                best.update({
                    "success": True,
                    "evidence": (
                        f"Login returned user profile (HTTP {r.status_code}, "
                        f"field combo: {ufield}/{pfield}, "
                        f"profile keys: {profile_hits})"
                    ),
                    "field_combo": f"{ufield}/{pfield}",
                })
                return best

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
# Session builder — feature parity with testConnection.py
# ─────────────────────────────────────────────────────────────

AUTH_METHODS: dict = {
    "form_login":           "Form Login — POST credentials → session cookies",
    "basic":                "HTTP Basic Auth (Authorization: Basic …)",
    "digest":               "HTTP Digest Auth (challenge-response)",
    "ntlm":                 "NTLM / Windows Integrated Auth (Active Directory)",
    "ntlm_v2":              "NTLMv2 + Channel Binding Token (EPA)",
    "bearer":               "Bearer Token (Authorization: Bearer …)",
    "session_cookie":       "Session Cookie — pre-captured cookie string",
    "token_login":          "Token Login — POST credentials → JSON token → Bearer header",
    "oauth2_client_creds":  "OAuth2 Client Credentials (machine-to-machine, RFC 6749 §4.4)",
    "oauth1a":              "OAuth 1.0a — HMAC-SHA1 signed request",
    "saml_assertion":       "SAML 2.0 — POST pre-captured SAMLResponse to ACS URL",
    "oidc_token":           "OIDC — pre-obtained id_token as Bearer",
    "mtls":                 "mTLS — mutual TLS with client certificate",
    "totp_mfa":             "TOTP/HOTP MFA — form login + TOTP second factor",
    "webauthn_probe":       "WebAuthn/FIDO2 — probe server for support (detection only)",
    "apikey_header":        "API Key in Header (custom header name)",
    "apikey_cookie":        "API Key / Token in Cookie",
    "header_creds":         "Custom Credential Headers (static key-value pairs)",
    "kerberos":             "Kerberos / SPNEGO Negotiate",
    "kerberos_delegation":  "Kerberos S4U2Proxy — constrained delegation",
    "proxy_header":         "Proxy / Gateway Auth Header",
    "auto":                 "Auto-detect — probe target + JS source mining + heuristics",
}


def _csrf_prefetch_ap(sess, login_url: str, timeout: int):
    """GET login_url; return (form_action_url, hidden_input_fields)."""
    try:
        r = sess.get(login_url, timeout=timeout)
        html = r.text
    except Exception:
        return "", {}
    hidden = {}
    form_action = ""
    for form_m in re.finditer(r"(?s)<form[^>]*>(.+?)</form>", html, re.IGNORECASE):
        form_tag = form_m.group(0)
        form_body = form_m.group(1)
        if not re.search(r'<input[^>]+type=["\']?password["\']?', form_body, re.I):
            continue
        act_m = re.search(r'\baction=["\']([^"\']*)["\']', form_tag, re.I)
        if act_m:
            raw = act_m.group(1).strip()
            if raw:
                form_action = urljoin(login_url, raw)
        for inp in re.finditer(r"<input[^>]+>", form_body, re.I):
            tag = inp.group(0)
            t_m = re.search(r'\btype=["\']?(\w+)["\']?', tag, re.I)
            if not t_m or t_m.group(1).lower() != "hidden":
                continue
            n_m = re.search(r'\bname=["\']([^"\']+)["\']', tag, re.I)
            v_m = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.I)
            if n_m:
                hidden[n_m.group(1)] = v_m.group(1) if v_m else ""
        break
    return form_action, hidden


def _login_post_ap(sess, auth: dict, timeout: int, allow_redirects: bool = True):
    """CSRF prefetch + POST credentials. Returns (response_or_None, post_url)."""
    url = auth.get("login_url", "")
    if not url:
        return None, ""
    login_mode = auth.get("login_mode", "fields")
    uf = auth.get("login_username_field", "username")
    pf = auth.get("login_password_field", "password")
    u = auth.get("username", "")
    p = auth.get("password", "")
    form_action, hidden = _csrf_prefetch_ap(sess, url, timeout)
    post_url = form_action if form_action else url
    if login_mode == "fields":
        data = dict(hidden)
        if u:
            data[uf] = u
        if p:
            data[pf] = p
    elif login_mode == "json":
        raw = auth.get("login_data", "{}")
        try:
            data = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            data = {}
    else:
        raw = auth.get("login_data", "{}")
        try:
            data = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            data = {}
        if u and uf not in data:
            data[uf] = u
        if p and pf not in data:
            data[pf] = p
        for k, v in hidden.items():
            if k not in data:
                data[k] = v
    ct = auth.get("login_content_type", "application/json")
    try:
        if "json" in ct:
            return sess.post(post_url, json=data, timeout=timeout,
                             allow_redirects=allow_redirects), post_url
        return sess.post(post_url, data=data, timeout=timeout,
                         allow_redirects=allow_redirects), post_url
    except Exception:
        return None, post_url


def _make_session_bs(proxy: str = "", timeout: int = 10, verify_ssl: bool = False):
    """Create a requests.Session with retry adapter for build_auth_session."""
    try:
        import requests as _req
        from requests.adapters import HTTPAdapter
        try:
            from urllib3.util.retry import Retry
        except ImportError:
            from requests.packages.urllib3.util.retry import Retry
    except ImportError:
        return None
    sess = _req.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    sess.mount("http://", HTTPAdapter(max_retries=retry))
    sess.mount("https://", HTTPAdapter(max_retries=retry))
    sess.verify = verify_ssl
    if proxy:
        sess.proxies = {"http": proxy, "https": proxy}
    sess.headers["User-Agent"] = f"AuthProbe/{VERSION}"
    return sess


def build_auth_session(
    auth: dict,
    timeout: int = 10,
    proxy: str = "",
    verify_ssl: bool = False,
):
    """
    Construct an authenticated requests.Session for the given auth config.
    Returns (session, info_message). info_message starts with "ERROR:" on failure.
    """
    _console.log("build_auth_session() starting", "INFO")
    sess = _make_session_bs(proxy, timeout, verify_ssl)
    if sess is None:
        _console.error("requests library not available")
        return None, "ERROR: requests library not available"
    method = (auth.get("method") or auth.get("auth_method")
              or auth.get("auth_type") or "form_login").strip().lower()
    _console.log(f"Auth method: {method}", "INFO")

    if method == "form_login":
        login_url = auth.get("login_url", "")
        if not login_url:
            return sess, "ERROR: login_url is required for form_login"
        resp, post_url = _login_post_ap(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {post_url or login_url} failed (network/timeout)"
        if not resp.ok:
            if resp.status_code == 405:
                return sess, (
                    f"ERROR: POST {post_url} → HTTP 405 Method Not Allowed — "
                    "check the HTML form action attribute")
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
                "login rejected (check credentials and login URL)")
        n = len(sess.cookies)
        sc = resp.status_code
        if n == 0:
            return sess, (
                f"WARNING: POST {post_url} → HTTP {sc} — "
                "login accepted but no session cookies returned")
        _console.log(f"form_login: {n} cookie(s) from {post_url}", "SUCCESS")
        return sess, f"POST {post_url} → HTTP {sc}, {n} cookie(s) stored"

    elif method == "basic":
        user = auth.get("username", "")
        pw = auth.get("password", "")
        if not user:
            return sess, "WARNING: no username provided for HTTP Basic"
        sess.auth = (user, pw)
        return sess, f"HTTP Basic: user={user}"

    elif method == "digest":
        try:
            from requests.auth import HTTPDigestAuth
        except ImportError:
            return sess, "ERROR: requests library required for digest auth"
        user = auth.get("username", "")
        pw = auth.get("password", "")
        if not user:
            return sess, "WARNING: no username provided for HTTP Digest"
        sess.auth = HTTPDigestAuth(user, pw)
        return sess, f"HTTP Digest: user={user}"

    elif method == "ntlm":
        user = auth.get("username", "")
        pw = auth.get("password", "")
        domain = auth.get("domain", "")
        if not user:
            return sess, "ERROR: username is required for NTLM"
        try:
            from requests_ntlm import HttpNtlmAuth
        except ImportError:
            return sess, "ERROR: NTLM auth requires: pip install requests-ntlm"
        domain = domain.rstrip("\\").strip()
        ntlm_user = f"{domain}\\{user}" if domain else user
        sess.auth = HttpNtlmAuth(ntlm_user, pw)
        return sess, f"NTLM: {ntlm_user}"

    elif method == "ntlm_v2":
        user = auth.get("username", "")
        pw = auth.get("password", "")
        domain = auth.get("domain", "").rstrip("\\").strip()
        if not user:
            return sess, "ERROR: username is required for ntlm_v2"
        try:
            from requests_ntlm import HttpNtlmAuth
        except ImportError:
            return sess, "ERROR: NTLMv2 requires: pip install requests-ntlm"
        ntlm_user = f"{domain}\\{user}" if domain else user
        try:
            sess.auth = HttpNtlmAuth(ntlm_user, pw, send_cbt=True)
        except TypeError:
            sess.auth = HttpNtlmAuth(ntlm_user, pw)
            return sess, f"NTLMv2 (send_cbt not supported): {ntlm_user}"
        return sess, f"NTLMv2 + channel binding: {ntlm_user}"

    elif method == "bearer":
        token = auth.get("auth_token", auth.get("token", "")).strip()
        if not token:
            return sess, "WARNING: no token provided for Bearer auth"
        tt = auth.get("token_type", "Bearer").strip()
        sess.headers["Authorization"] = f"{tt} {token}"
        return sess, f"Authorization: {tt} ***"

    elif method == "session_cookie":
        raw = auth.get("session_cookie", "").strip()
        if not raw:
            return sess, "WARNING: no session_cookie value provided"
        names = []
        for part in raw.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                k, _, v = part.partition("=")
                sess.cookies.set(k.strip(), v.strip())
                names.append(k.strip())
            else:
                sess.cookies.set(part, "")
                names.append(part)
        return sess, f"Session cookie(s) set: {', '.join(names)}"

    elif method == "token_login":
        login_url = auth.get("login_url", "")
        if not login_url:
            return sess, "ERROR: login_url is required for token_login"
        resp, post_url = _login_post_ap(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {post_url or login_url} failed (network/timeout)"
        if not resp.ok:
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
                "login rejected (check credentials and login URL)")
        try:
            body = resp.json()
        except Exception:
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
                "response is not JSON; cannot extract token")
        token_path = auth.get("login_token_path", "token")
        token = body
        for part in token_path.split("."):
            token = token.get(part) if isinstance(token, dict) else None
        if not token or not isinstance(token, str):
            for k in ("token", "access_token", "jwt", "id_token", "auth_token"):
                if k in body:
                    token = body[k]
                    break
        if token is not None and token != "":
            token = str(token)
            tt = auth.get("token_type", "Bearer").strip()
            sess.headers["Authorization"] = f"{tt} {token}"
            _console.log(f"token_login: token extracted via path='{token_path}'", "SUCCESS")
            return sess, (
                f"POST {post_url} → HTTP {resp.status_code}; "
                f"token extracted via path='{token_path}'")
        return sess, (
            f"ERROR: POST {post_url} → HTTP {resp.status_code}; "
            f"no token found at path='{token_path}'")

    elif method == "oauth2_client_creds":
        token_url = auth.get("oauth_token_url", "")
        client_id = auth.get("oauth_client_id", "")
        client_secret = auth.get("oauth_client_secret", "")
        scope = auth.get("oauth_scope", "")
        if not token_url:
            return sess, "ERROR: oauth_token_url is required"
        if not client_id:
            return sess, "ERROR: oauth_client_id is required"
        client_auth_method = auth.get("client_auth_method", "body").strip().lower()
        data = {"grant_type": "client_credentials"}
        req_kwargs = {"timeout": timeout}
        if client_auth_method == "basic":
            req_kwargs["auth"] = (client_id, client_secret)
        else:
            data["client_id"] = client_id
            data["client_secret"] = client_secret
        if scope:
            data["scope"] = scope
        try:
            resp = sess.post(token_url, data=data, **req_kwargs)
        except Exception as exc:
            return sess, f"ERROR: OAuth2 token request failed: {exc}"
        if not resp.ok:
            return sess, (
                f"ERROR: OAuth2 POST {token_url} → HTTP {resp.status_code} — "
                "token request rejected")
        try:
            body = resp.json()
        except Exception:
            return sess, (
                f"ERROR: OAuth2 POST {token_url} → HTTP {resp.status_code} — "
                "response is not JSON")
        access_token = body.get("access_token", "")
        if not access_token:
            return sess, (
                f"ERROR: OAuth2 POST {token_url} → HTTP {resp.status_code}; "
                "no access_token in response")
        tt = body.get("token_type", "Bearer")
        sess.headers["Authorization"] = f"{tt} {access_token}"
        _console.log(f"OAuth2 token obtained from {token_url}", "SUCCESS")
        return sess, f"OAuth2 token obtained from {token_url} → HTTP {resp.status_code}"

    elif method == "oauth1a":
        consumer_key = auth.get("oauth1_consumer_key", "").strip()
        consumer_secret = auth.get("oauth1_consumer_secret", "").strip()
        access_token = auth.get("oauth1_access_token", "").strip()
        token_secret = auth.get("oauth1_token_secret", "").strip()
        if not consumer_key:
            return sess, "ERROR: oauth1_consumer_key is required for oauth1a"
        try:
            from requests_oauthlib import OAuth1
        except ImportError:
            return sess, "ERROR: OAuth 1.0a requires: pip install requests-oauthlib"
        sess.auth = OAuth1(consumer_key, consumer_secret,
                           access_token or None, token_secret or None)
        return sess, f"OAuth 1.0a configured (consumer={consumer_key})"

    elif method == "saml_assertion":
        acs_url = auth.get("saml_acs_url", "").strip()
        assertion = auth.get("saml_assertion", "").strip()
        relay_state = auth.get("saml_relay_state", "")
        if not acs_url:
            return sess, "ERROR: saml_acs_url is required for saml_assertion"
        if not assertion:
            return sess, "ERROR: saml_assertion (base64-encoded SAMLResponse) is required"
        try:
            data = {"SAMLResponse": assertion}
            if relay_state:
                data["RelayState"] = relay_state
            resp = sess.post(acs_url, data=data, timeout=timeout, allow_redirects=True)
            if resp.status_code in (401, 403):
                return sess, (
                    f"ERROR: SAML POST to {acs_url} → HTTP {resp.status_code} — "
                    "assertion rejected")
            return sess, f"SAML assertion posted to {acs_url} → HTTP {resp.status_code}"
        except Exception as exc:
            return sess, f"ERROR: SAML POST failed: {exc}"

    elif method == "oidc_token":
        id_token = auth.get("oidc_id_token", "").strip()
        userinfo = auth.get("oidc_userinfo_url", "").strip()
        if not id_token:
            return sess, "ERROR: oidc_id_token is required for oidc_token"
        sess.headers["Authorization"] = f"Bearer {id_token}"
        if not userinfo:
            return sess, "OIDC id_token set as Bearer (no userinfo_url provided)"
        try:
            r = sess.get(userinfo, timeout=timeout)
            if r.status_code == 401:
                return sess, f"ERROR: OIDC userinfo {userinfo} → HTTP 401 — token rejected"
            return sess, f"OIDC id_token valid — userinfo {userinfo} → HTTP {r.status_code}"
        except Exception as exc:
            return sess, f"OIDC id_token set; userinfo probe failed: {exc}"

    elif method == "mtls":
        cert_path = auth.get("mtls_cert", "").strip()
        key_path = auth.get("mtls_key", "").strip()
        ca_bundle = auth.get("mtls_ca_bundle", "").strip()
        if not cert_path:
            return sess, "ERROR: mtls_cert (path to PEM certificate) is required"
        if not key_path:
            return sess, "ERROR: mtls_key (path to PEM private key) is required"
        if not os.path.isfile(cert_path):
            return sess, f"ERROR: mtls_cert file not found: {cert_path}"
        if not os.path.isfile(key_path):
            return sess, f"ERROR: mtls_key file not found: {key_path}"
        sess.cert = (cert_path, key_path)
        if ca_bundle and os.path.isfile(ca_bundle):
            sess.verify = ca_bundle
        return sess, f"mTLS client cert configured: {cert_path}"

    elif method == "totp_mfa":
        login_url = auth.get("login_url", "")
        mfa_url = auth.get("totp_mfa_url", "").strip()
        totp_secret = auth.get("totp_secret", "").strip()
        mfa_field = auth.get("totp_field", "otp")
        if not login_url:
            return sess, "ERROR: login_url is required for totp_mfa"
        resp, post_url = _login_post_ap(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {post_url or login_url} failed (network/timeout)"
        if not resp.ok:
            if resp.status_code == 405:
                return sess, (
                    f"ERROR: POST {post_url} → HTTP 405 Method Not Allowed — "
                    "check the HTML form action attribute")
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
                "primary login rejected")
        if not mfa_url:
            return sess, (
                f"POST {post_url} → HTTP {resp.status_code} (primary OK); "
                "no totp_mfa_url provided — skipping MFA step")
        if not totp_secret:
            return sess, (
                f"POST {post_url} → HTTP {resp.status_code} (primary OK); "
                "no totp_secret provided — cannot generate OTP")
        try:
            import hmac as _hmac
            import hashlib as _hl
            import struct as _struct
            import time as _time
            import base64 as _b64
            def _totp(secret, digits=6, period=30):
                key = _b64.b32decode(secret.upper().replace(" ", ""))
                t = int(_time.time()) // period
                msg = _struct.pack(">Q", t)
                h = _hmac.new(key, msg, _hl.sha1).digest()
                off = h[-1] & 0x0F
                code = (_struct.unpack(">I", h[off:off+4])[0] & 0x7FFFFFFF) % (10 ** digits)
                return str(code).zfill(digits)
            otp = _totp(totp_secret)
            mfa_resp = sess.post(mfa_url, data={mfa_field: otp}, timeout=timeout)
            if not mfa_resp.ok:
                return sess, (
                    f"ERROR: MFA POST {mfa_url} → HTTP {mfa_resp.status_code} — "
                    "second factor rejected")
            _console.log(f"TOTP MFA accepted at {mfa_url}", "SUCCESS")
            return sess, (
                f"POST {post_url} → HTTP {resp.status_code}; "
                f"MFA POST {mfa_url} → HTTP {mfa_resp.status_code} (OTP accepted)")
        except Exception as exc:
            return sess, f"ERROR: TOTP MFA step failed: {exc}"

    elif method == "webauthn_probe":
        probe_url = auth.get("webauthn_probe_url", "").strip()
        try:
            r = sess.get(probe_url, timeout=timeout) if probe_url else None
        except Exception:
            r = None
        indicators = []
        if r is not None:
            body = r.text
            if "webauthn" in body.lower() or "fido" in body.lower():
                indicators.append("WebAuthn/FIDO keywords in page body")
            if "/.well-known/webauthn" in body or "PublicKeyCredential" in body:
                indicators.append("WebAuthn API reference detected")
        if indicators:
            return sess, f"WebAuthn support detected: {'; '.join(indicators)}"
        return sess, "WebAuthn probe complete — no indicators found"

    elif method == "apikey_header":
        key = auth.get("api_key", "").strip()
        header = auth.get("api_key_header", "X-API-Key")
        if not key:
            return sess, "WARNING: no api_key provided for apikey_header"
        sess.headers[header] = key
        return sess, f"{header}: ***"

    elif method == "apikey_cookie":
        key = auth.get("api_key", "").strip()
        cookie_name = auth.get("api_key_cookie", "api_key")
        if not key:
            return sess, "WARNING: no api_key provided for apikey_cookie"
        sess.cookies.set(cookie_name, key)
        return sess, f"Cookie {cookie_name}=***"

    elif method == "header_creds":
        hdrs = auth.get("custom_headers", {})
        if not isinstance(hdrs, dict) or not hdrs:
            return sess, "WARNING: no custom_headers provided"
        sess.headers.update(hdrs)
        names = list(hdrs.keys())
        return sess, f"Set {len(names)} header(s): {', '.join(names)}"

    elif method == "kerberos":
        try:
            from requests_kerberos import HTTPKerberosAuth, OPTIONAL
        except ImportError:
            return sess, "ERROR: Kerberos auth requires: pip install requests-kerberos"
        sess.auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
        return sess, "Kerberos SPNEGO auth configured"

    elif method == "kerberos_delegation":
        try:
            from requests_kerberos import HTTPKerberosAuth, REQUIRED
        except ImportError:
            return sess, "ERROR: Kerberos delegation requires: pip install requests-kerberos"
        impersonate = auth.get("kerberos_impersonate", "")
        kwargs = {"mutual_authentication": REQUIRED, "delegate": True}
        if impersonate:
            kwargs["principal"] = impersonate
        sess.auth = HTTPKerberosAuth(**kwargs)
        detail = (f"Kerberos delegation configured (impersonate={impersonate})"
                  if impersonate else "Kerberos S4U2Proxy delegation configured")
        return sess, detail

    elif method == "proxy_header":
        hdr_name = auth.get("proxy_header_name", "X-Remote-User").strip()
        hdr_value = auth.get("proxy_header_value", "").strip()
        if not hdr_value:
            return sess, f"WARNING: no proxy_header_value provided for header '{hdr_name}'"
        sess.headers[hdr_name] = hdr_value
        return sess, f"Proxy auth header set: {hdr_name}: {hdr_value}"

    elif method == "auto":
        _console.log("auto-detect: probing target for auth signals", "INFO")
        target_url = auth.get("_target_url", auth.get("login_url", ""))
        has_creds = bool(auth.get("username"))
        if not has_creds:
            return sess, "ERROR: auto-detect needs credentials (username/password)"

        _errors = []
        # Try HTTP-level auth first (401 + WWW-Authenticate)
        try:
            r = sess.get(target_url, timeout=timeout, allow_redirects=False)
            if r.status_code == 401:
                www = r.headers.get("WWW-Authenticate", "")
                if "ntlm" in www.lower() or "negotiate" in www.lower():
                    _console.log("auto-detect: NTLM/Negotiate detected", "INFO")
                    auth["method"] = "ntlm"
                    return build_auth_session(auth, timeout, proxy, verify_ssl)
                if "basic" in www.lower():
                    _console.log("auto-detect: Basic auth detected", "INFO")
                    auth["method"] = "basic"
                    return build_auth_session(auth, timeout, proxy, verify_ssl)
                if "digest" in www.lower():
                    auth["method"] = "digest"
                    return build_auth_session(auth, timeout, proxy, verify_ssl)
        except Exception:
            pass

        # Try form login
        login_url = auth.get("login_url", "")
        if not login_url:
            _heuristic_paths = [
                "/login", "/signin", "/sign-in", "/auth/login",
                "/account/login", "/session/new", "/users/sign_in",
                "/wp-login.php", "/admin/login",
            ]
            parsed = urlparse(target_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for p in _heuristic_paths:
                try:
                    r = sess.get(origin + p, timeout=timeout, allow_redirects=True)
                    if r.status_code == 200 and re.search(
                            r'<input[^>]+type=["\']?password', r.text, re.I):
                        login_url = origin + p
                        _console.log(f"auto-detect: found login form at {login_url}", "INFO")
                        break
                except Exception:
                    continue

        if login_url:
            auth["login_url"] = login_url
            auth["method"] = "form_login"
            s, msg = build_auth_session(auth, timeout, proxy, verify_ssl)
            if not msg.startswith("ERROR:"):
                _console.log(f"auto-detect → form_login ({login_url})", "SUCCESS")
                return s, f"auto-detect → form_login ({login_url}): {msg}"
            _errors.append(f"form_login: {msg}")

            # Try as token_login (JSON API)
            auth["method"] = "token_login"
            auth["login_content_type"] = "application/json"
            s2, msg2 = build_auth_session(auth, timeout, proxy, verify_ssl)
            if not msg2.startswith("ERROR:"):
                _console.log(f"auto-detect → token_login ({login_url})", "SUCCESS")
                return s2, f"auto-detect → token_login ({login_url}): {msg2}"
            _errors.append(f"token_login: {msg2}")

        if _errors:
            return sess, "ERROR: auto-detect exhausted all methods — " + "; ".join(_errors)
        return sess, "ERROR: auto-detect found no login form and no 401 challenge"

    return sess, f"WARNING: unknown auth method '{method}'"


# ─────────────────────────────────────────────────────────────
# Login-profile store integration
# ─────────────────────────────────────────────────────────────
_LP_INDEX_PATH_AP = Path("/opt/pr0t31n/Fracture/login_profiles/index.json")


def _lp_fingerprint_url_ap(url: str) -> dict:
    """Minimal structural fingerprint of *url*'s login page for profile matching."""
    import html.parser as _hp
    fp: dict = {
        "input_count":        0,
        "has_password_field": False,
        "has_hidden_fields":  False,
        "hidden_field_count": 0,
        "form_action_path":   "",
        "form_action_depth":  0,
        "form_method":        "POST",
        "login_path":         "",
        "framework_hints":    [],
    }
    try:
        import requests as _req
        r   = _req.get(url, timeout=8, verify=False, allow_redirects=True)
        htm = r.text
        fp["login_path"] = urlparse(r.url).path.rstrip("/").split("/")[-1].lower()

        class _P(_hp.HTMLParser):
            def __init__(self):
                super().__init__()
                self.in_form = False
                self.inputs: list = []
                self.faction = ""
                self.fmethod = "POST"

            def handle_starttag(self, tag, attrs):
                a = dict(attrs)
                if tag == "form":
                    self.in_form = True
                    self.faction = a.get("action", "")
                    self.fmethod = (a.get("method") or "post").upper()
                elif tag == "input" and self.in_form:
                    self.inputs.append(a)

            def handle_endtag(self, tag):
                if tag == "form":
                    self.in_form = False

        p = _P()
        p.feed(htm)
        fp["input_count"]        = len(p.inputs)
        fp["has_password_field"] = any(i.get("type", "").lower() == "password"
                                       for i in p.inputs)
        hidden                   = [i for i in p.inputs
                                    if i.get("type", "").lower() == "hidden"]
        fp["has_hidden_fields"]  = bool(hidden)
        fp["hidden_field_count"] = len(hidden)
        fp["form_method"]        = p.fmethod
        if p.faction:
            _ap = urlparse(p.faction).path
            fp["form_action_path"]  = _ap
            fp["form_action_depth"] = len([s for s in _ap.split("/") if s])

        _fh: list = []
        if "wp-login" in htm or "WordPress" in htm:
            _fh.append("wordpress")
        if "csrfmiddlewaretoken" in htm or "django" in htm.lower():
            _fh.append("django")
        if 'name="_token"' in htm or "laravel" in htm.lower():
            _fh.append("laravel")
        if "authenticity_token" in htm:
            _fh.append("rails")
        fp["framework_hints"] = _fh
    except Exception:
        pass
    return fp


def _lp_score_ap(observed: dict, stored: dict) -> float:
    """Score observed fingerprint against a stored profile fingerprint."""
    pts = total = 0.0

    def _w(key: str, weight: float) -> None:
        nonlocal pts, total
        total += weight
        if observed.get(key) == stored.get(key):
            pts += weight

    _w("has_password_field", 3.0)
    _w("has_hidden_fields",  2.0)
    _w("form_method",        1.0)
    _w("form_action_depth",  1.0)
    total += 2.0
    diff   = abs(observed.get("input_count", 0) - stored.get("input_count", 0))
    pts   += 2.0 if diff == 0 else (1.0 if diff == 1 else 0.0)
    o_h    = set(observed.get("framework_hints", []))
    s_h    = set(stored.get("framework_hints",  []))
    total += 2.0
    if o_h and s_h:
        pts += 2.0 * len(o_h & s_h) / max(len(o_h), len(s_h))
    elif not o_h and not s_h:
        pts += 2.0
    total += 1.0
    o_p    = observed.get("login_path", "").lower()
    s_p    = stored.get("login_path",  "").lower()
    if o_p and s_p:
        if o_p == s_p:
            pts += 1.0
        elif o_p in s_p or s_p in o_p:
            pts += 0.5
    return round(pts / total, 3) if total > 0 else 0.0


def _lp_match_from_index(url: str) -> "dict | None":
    """
    Check the Fracture login-profile index for a structural match against *url*.
    Returns the best matching index entry with an added 'confidence' key (0-100),
    or None if the index is absent or no entry scores >= 75%.
    """
    if not _LP_INDEX_PATH_AP.exists():
        return None
    try:
        index = json.loads(_LP_INDEX_PATH_AP.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not index:
        return None
    observed = _lp_fingerprint_url_ap(url)
    best_s: float         = 0.0
    best_e: "dict | None" = None
    for entry in index:
        s = _lp_score_ap(observed, entry.get("fingerprint", {}))
        if s > best_s:
            best_s = s
            best_e = entry
    if best_s >= 0.75 and best_e:
        return {**best_e, "confidence": int(best_s * 100)}
    return None


# ─────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────

def _print_section(title):
    _console.log(f"━━━ {title} ━━━", "INFO")
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

    # Software fingerprints
    if findings.get("software_matches"):
        _print_section("IDENTIFIED SOFTWARE / PORTAL")
        for sw in findings["software_matches"][:5]:
            conf = sw.get("confidence", 0)
            colour = green if conf >= 60 else yellow
            print(f"  {colour(f'[{conf:3d}%]')}  {bold(sw['name'])}")
            for sig in sw.get("indicators", [])[:2]:
                print(f"          {dim(sig)}")
            if sw.get("login_url_hint"):
                print(f"          {dim('login hint: ' + sw['login_url_hint'])}")

    # URL type classification
    if findings.get("url_type"):
        _print_section(f"URL TYPE: {findings['url_type'].upper()}")
        conf = findings.get("url_type_confidence", 0)
        colour = green if conf >= 60 else yellow
        print(f"  Confidence: {colour(str(conf) + '%')}")

    # Well-known endpoints
    if findings.get("well_known"):
        _print_section("WELL-KNOWN / SPEC ENDPOINTS")
        for key, info in findings["well_known"].items():
            sc = info["status_code"]
            colour = green if sc == 200 else yellow
            print(f"  {colour(str(sc))}  {key}: {info['url']}")

    if findings.get("rendered_dom_signals"):
        _print_section("RENDERED DOM SIGNALS")
        for sig in findings["rendered_dom_signals"]:
            print(f"  {cyan('»')}  {dim(sig)}")

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

    if findings.get("login_profile_match"):
        _lpm = findings["login_profile_match"]
        _print_section("LOGIN PROFILE MATCH")
        _conf = _lpm.get("confidence", 0)
        _conf_colour = green if _conf >= 90 else (yellow if _conf >= 75 else red)
        print(f"  {green('✓')}  Profile ID:    {bold(_lpm.get('id','?'))}")
        print(f"       Confidence:  {_conf_colour(str(_conf) + '%')}")
        print(f"       Recorded on: {dim(_lpm.get('target_url','?'))}")
        print(f"       Created:     {dim(_lpm.get('created','?'))}")
        print(f"       Description: {dim(_lpm.get('description',''))}")
        print(f"\n  {dim('Fracture will replay this profile automatically.')}")
        print(f"  {dim('To override, set fr_auth_login_profile_id to a different profile ID')}")
        print(f"  {dim('or set it to empty to force a fresh browser-assisted login.')}")

    _print_section("RECOMMENDED AUTH METHOD FOR FRACTURE / SIPHON")
    # Validated methods take priority over detected-only methods
    _form_confirmed_url  = findings.get("form_login_confirmed_url", "")
    _token_confirmed_url = findings.get("token_login_url", "")
    sw_matches = findings.get("software_matches", [])
    if sw_matches and sw_matches[0].get("auth_hints"):
        best_method = sw_matches[0]["auth_hints"][0]
        print(f"  → {bold(best_method)}  (based on {sw_matches[0]['name']} fingerprint)")
    elif findings.get("ntlm_detected"):
        print(f"  → {bold('ntlm')}  (requires requests-ntlm)")
    elif findings.get("kerberos_detected"):
        print(f"  → {bold('kerberos')}  (requires requests-kerberos + kinit)")
    elif findings.get("oauth_discovery"):
        print(f"  → {bold('oauth2_client_creds')}  (or bearer with pre-obtained token)")
    elif _form_confirmed_url:
        print(f"  → {bold('form_login')}  {green('(validated)')}  (POST credentials to {_form_confirmed_url})")
    elif _token_confirmed_url:
        print(f"  → {bold('token_login')}  {green('(validated)')}  (POST credentials to {_token_confirmed_url})")
    elif findings.get("json_api_auth"):
        url = findings.get("json_api_auth_url", "")
        print(f"  → {bold('token_login')}  (POST credentials to {url})")
    elif findings.get("form_login"):
        print(f"  → {bold('form_login')}  (POST credentials to login form — not yet validated)")
    elif findings.get("token_login_likely"):
        url = findings.get("token_login_url", "")
        print(f"  → {bold('token_login')}  (POST credentials to {url})")
    elif findings.get("basic_auth") is not None:
        print(f"  → {bold('basic')}  (HTTP Basic Auth)")
    elif findings.get("session_cookies"):
        print(f"  → {bold('session_cookie')}  (inject pre-captured cookie)")
    elif findings.get("api_key_header_hints"):
        print(f"  → {bold('apikey_header')}  (set key in request header)")
    else:
        print(f"  → {yellow('unknown')}  (manual inspection recommended)")

    # Fracture / Siphon config snippet — shown for any validated login method
    if _form_confirmed_url:
        vr = findings.get("validation_results", [])
        fl = next((r for r in vr if r.get("method") == "form_login" and r.get("success")), None)
        uf = (fl.get("username_field", "username") if fl else "username")
        pf = (fl.get("password_field", "password") if fl else "password")
        print(f"\n  {dim('Fracture / Siphon config snippet:')}")
        print(f'  {dim("scan.auth.method")}                = {cyan("form_login")}')
        print(f'  {dim("scan.auth.login_url")}             = {cyan(_form_confirmed_url)}')
        print(f'  {dim("scan.auth.login_username_field")}  = {cyan(uf)}')
        print(f'  {dim("scan.auth.login_password_field")}  = {cyan(pf)}')
        print(f'  {dim("scan.auth.login_content_type")}    = {cyan("application/x-www-form-urlencoded")}')
    elif findings.get("json_api_auth") or _token_confirmed_url:
        url = _token_confirmed_url or findings.get("json_api_auth_url", "")
        vr  = findings.get("validation_results", [])
        tl  = next((r for r in vr if r.get("method") == "token_login"), None)
        combo_hint = f"  # field combo: {tl['field_combo']}" if tl and tl.get("field_combo") else ""
        print(f"\n  {dim('Fracture / Siphon config snippet:')}")
        print(f'  {dim("scan.auth.method")}           = {cyan("token_login")}')
        print(f'  {dim("scan.auth.login_url")}        = {cyan(url)}')
        if combo_hint:
            print(f'  {dim(combo_hint)}')


# ─────────────────────────────────────────────────────────────
# AuthProbe class — callable API for Fracture/Siphon
# ─────────────────────────────────────────────────────────────

class AuthProbe:
    """
    Importable probe API for use by Fracture and Siphon testConnection.py.

    Usage::

        from authprobe import AuthProbe
        result = AuthProbe(timeout=10).probe("https://target.example.com")

    Result dict::

        {
          "url":                  str,
          "url_type":             "api" | "webapp" | "hybrid" | "unknown",
          "url_type_confidence":  0-100,
          "auth_methods":         [{"method": str, "confidence": int, "notes": str}],
          "software":             [{"name": str, "confidence": int, "indicators": [...]}],
          "recommendations":      [str],   # ordered method names
          "findings":             dict,    # full findings dict for advanced use
        }
    """

    def __init__(
        self,
        timeout: int = 10,
        proxy: str = "",
        verify_ssl: bool = False,
        rendered: bool = False,
        driver_path: str = "",
    ) -> None:
        self.timeout     = timeout
        self.proxy       = proxy
        self.verify_ssl  = verify_ssl
        self.rendered    = rendered
        self.driver_path = driver_path

    def probe(self, url: str) -> dict:
        """Probe *url* and return a structured detection result."""
        _console.log(f"AuthProbe.probe() starting for {url}", "INFO")
        sess = _make_session_raw(proxy=self.proxy, timeout=self.timeout)
        if sess is None:
            _console.error(f"requests library not available for {url}")
            return self._error(url, "requests library not available")

        findings: dict = {
            "www_authenticate":      [],
            "form_login":            False,
            "form_login_evidence":   [],
            "json_api_auth":         False,
            "json_api_auth_url":     "",
            "json_api_cred_checked": False,
            "token_login_likely":    False,
            "token_login_url":       "",
            "oauth_discovery":       [],
            "session_cookies":       [],
            "api_key_header_hints":  [],
            "apikey_cookie_hints":   [],
            "login_endpoints":       [],
            "security_headers":      {},
            "basic_auth":            None,
            "ntlm_detected":         False,
            "kerberos_detected":     False,
            "validation_results":    [],
            "software_matches":      [],
            "well_known":            {},
            "auth_info_mode":        "",
            "url_type":              "unknown",
            "url_type_confidence":   0,
        }

        raw_url = url.rstrip("/")
        parsed  = urlparse(raw_url)
        if not parsed.scheme:
            raw_url = "https://" + raw_url
            parsed  = urlparse(raw_url)

        origin, url_path, full_url = _split_url(raw_url)
        given_is_login  = _is_login_path(url_path)
        skip_paths: set = {url_path.rstrip("/")} if given_is_login else set()

        # Auto-detect type for login endpoint probing
        path_lc = url_path.lower()
        if re.search(r'/api/|/v\d+/', path_lc) or "api." in parsed.netloc.lower():
            probe_type = "api"
        else:
            probe_type = "webapp"

        # Phase 1: Probe primary URL
        _console.log(f"[probe] Phase 1: Probing {full_url}...", "INFO")
        base_resp = _safe_get(sess, full_url, self.timeout)
        if base_resp is None:
            _console.error(f"All HTTP probes to {full_url} failed (network/timeout)")
            return self._error(url, "All HTTP probes failed (network/timeout)")
        _console.log(f"[probe] Phase 1: Target responded HTTP {base_resp.status_code}", "SUCCESS")

        body = ""
        try:
            body = base_resp.text[:8000]
        except Exception:
            pass

        # Phase 2: Detect standard auth signals
        _console.log("[probe] Phase 2: Detecting auth signals...", "INFO")
        detect_www_authenticate(base_resp, findings)
        detect_basic_auth(base_resp, findings)
        detect_ntlm_kerberos(base_resp, findings)
        detect_form_login(base_resp, findings)
        detect_json_api_auth(base_resp, full_url, findings)
        detect_token_login_response(base_resp, full_url, findings)
        detect_session_cookies(base_resp, findings)
        detect_apikey_cookie(base_resp, findings)
        detect_security_headers(base_resp, findings)

        # Phase 3: Software fingerprinting (static HTML)
        _console.log("[probe] Phase 3: Software fingerprinting...", "INFO")
        cookie_names = [c.name for c in base_resp.cookies]
        sw_matches = fingerprint_software(
            full_url, dict(base_resp.headers), body, cookie_names
        )

        if sw_matches:
            _console.log(f"[probe] Phase 3: Identified: {', '.join(sw['name'] for sw in sw_matches[:3])}", "SUCCESS")

        # Phase 3b: Rendered-page fingerprinting (Selenium) if enabled
        if self.rendered:
            rendered_result = fingerprint_rendered(
                full_url,
                timeout=self.timeout + 5,
                proxy=self.proxy,
                driver_path=self.driver_path,
            )
            findings["rendered"] = rendered_result
            # Merge rendered software matches (higher confidence wins)
            existing_names = {m["name"] for m in sw_matches}
            for rm in rendered_result.get("software_matches", []):
                if rm["name"] not in existing_names:
                    sw_matches.append(rm)
                    existing_names.add(rm["name"])
                else:
                    # Boost existing match confidence if rendered confirms it
                    for m in sw_matches:
                        if m["name"] == rm["name"]:
                            m["confidence"] = min(m["confidence"] + 20, 95)
                            m["indicators"] += [
                                f"[rendered] {s}" for s in rm.get("indicators", [])
                            ]
            # Inject rendered DOM signals into findings
            findings["rendered_dom_signals"] = rendered_result.get("dom_signals", [])
            # Re-run body-based signals on rendered HTML
            rendered_body = (
                rendered_result.get("rendered_html", "")
                + "\n" + rendered_result.get("visible_text", "")
            )
            if rendered_body.strip():
                detect_form_login(
                    type("_FakeResp", (), {
                        "status_code": 200,
                        "headers": {"Content-Type": "text/html"},
                        "text": rendered_body,
                    })(),
                    findings,
                )

        sw_matches.sort(key=lambda x: x["confidence"], reverse=True)
        findings["software_matches"] = sw_matches

        # Phase 4: Well-known / spec endpoint discovery
        _console.log("[probe] Phase 4: Probing well-known endpoints...", "INFO")
        well_known = probe_well_known(sess, full_url, self.timeout)
        if well_known:
            _console.log(f"[probe] Phase 4: Found: {', '.join(well_known.keys())}", "SUCCESS")
        findings["well_known"] = well_known

        # Phase 4b: Auth challenges from well-known probe responses
        for _wk_info in well_known.values():
            ww = _wk_info.get("www_authenticate", "").lower()
            if "negotiate" in ww:
                findings["kerberos_detected"] = True
            if "ntlm" in ww:
                findings["ntlm_detected"] = True
            if "basic" in ww and findings.get("basic_auth") is None:
                findings["basic_auth"] = {"realm": ""}

        # Phase 4c: /auth-info hint parsing
        _ai = well_known.get("auth_info", {})
        if _ai.get("is_json") and _ai.get("body_snip"):
            try:
                import json as _json
                _ai_body = _json.loads(_ai["body_snip"]
                                       if len(_ai["body_snip"]) < 290
                                       else _safe_get(sess,
                                           _ai["url"], self.timeout).text)
                findings["auth_info_mode"] = _ai_body.get("auth_mode", "")
            except Exception:
                pass

        # Phase 5: URL type classification
        _console.log("[probe] Phase 5: Classifying URL type...", "INFO")
        url_type, url_type_conf = classify_url_type(
            full_url, base_resp, body, well_known, sw_matches
        )
        findings["url_type"]              = url_type
        findings["url_type_confidence"]   = url_type_conf
        _console.log(f"[probe] Phase 5: URL type: {url_type} ({url_type_conf}%)", "SUCCESS")

        # Phase 6: Login endpoint discovery
        _console.log("[probe] Phase 6: Login endpoint discovery...", "INFO")
        if given_is_login:
            findings["login_endpoints"].append({
                "path": url_path,
                "status": base_resp.status_code,
                "content_type": base_resp.headers.get("Content-Type", "")[:60],
            })
        detect_login_endpoints(sess, origin, self.timeout, probe_type,
                               skip_paths, findings)
        detect_oauth_discovery(sess, origin, self.timeout, findings)

        # Phase 7: Build auth_methods list from all signals
        _console.log("[probe] Phase 7: Building auth method confidence scores...", "INFO")
        auth_methods = self._build_auth_methods(findings, sw_matches, well_known)

        if auth_methods:
            _console.log(f"[probe] Phase 7: Top auth method: {auth_methods[0]['method']} "
                         f"({auth_methods[0]['confidence']}% confidence)", "SUCCESS")

        # Phase 8: Recommendations
        _console.log("[probe] Phase 8: Building recommendations...", "INFO")
        recommendations = [m["method"] for m in auth_methods if m["confidence"] >= 40]
        if not recommendations:
            recommendations = [m["method"] for m in auth_methods[:3]]

        _console.log(f"AuthProbe.probe() complete for {full_url} — "
                     f"{len(auth_methods)} auth method(s), {len(recommendations)} recommendation(s)", "SUCCESS")

        return {
            "url":                  full_url,
            "url_type":             url_type,
            "url_type_confidence":  url_type_conf,
            "auth_methods":         auth_methods,
            "software":             sw_matches,
            "recommendations":      recommendations,
            "findings":             findings,
        }

    def _build_auth_methods(
        self,
        findings: dict,
        sw_matches: list,
        well_known: dict,
    ) -> list[dict]:
        """Derive a confidence-scored auth method list from findings."""
        scores: dict[str, dict] = {}

        def _add(method: str, delta: int, signal: str) -> None:
            if method not in scores:
                scores[method] = {"confidence": 0, "signals": []}
            scores[method]["confidence"] = min(scores[method]["confidence"] + delta, 95)
            scores[method]["signals"].append(signal)

        # WWW-Authenticate
        for entry in findings.get("www_authenticate", []):
            scheme = entry["scheme"]
            method_map = {"basic": "basic", "digest": "digest", "bearer": "bearer",
                          "ntlm": "ntlm", "negotiate": "kerberos", "oauth": "oauth2_client_creds"}
            if scheme in method_map:
                _add(method_map[scheme], 70, f"WWW-Authenticate: {entry['header'][:60]}")

        # NTLM / Kerberos
        if findings.get("ntlm_detected"):
            _add("ntlm", 65, "NTLM detected in WWW-Authenticate")
            _add("ntlm_v2", 40, "NTLM v2 likely alongside NTLM")
        if findings.get("kerberos_detected"):
            _add("kerberos", 65, "Negotiate/Kerberos detected in WWW-Authenticate")
            _add("kerberos_delegation", 55, "Negotiate header — delegation variant possible")

        # /auth-info hint (app self-reported auth mode)
        _ai_mode = findings.get("auth_info_mode", "")
        if _ai_mode:
            _add(_ai_mode, 80, f"/auth-info reports auth_mode={_ai_mode}")
            # If delegation reported, also score base kerberos
            if _ai_mode == "kerberos_delegation":
                _add("kerberos", 50, "kerberos_delegation implies kerberos capable")

        # Basic auth
        if findings.get("basic_auth") is not None:
            _add("basic", 60, f"HTTP Basic Auth — realm={findings['basic_auth'].get('realm', '')}")

        # Form login
        if findings.get("form_login"):
            _add("form_login", 65, "HTML login form detected")

        # JSON API / token login
        if findings.get("json_api_auth"):
            _add("token_login", 55, f"JSON API auth endpoint: {findings['json_api_auth_url']}")
        if findings.get("token_login_likely"):
            _add("token_login", 60, f"Token response found at: {findings['token_login_url']}")

        # OAuth discovery
        for entry in findings.get("oauth_discovery", []):
            _add("oauth2_client_creds", 65,
                 f"OAuth2/OIDC discovery: {entry.get('issuer', '?')}")
            _add("oidc_token", 50, "OIDC discovered")
            _add("bearer", 40, "OAuth2 implies Bearer token")

        # Session cookies
        if findings.get("session_cookies"):
            _add("session_cookie", 40,
                 f"Session cookies: {', '.join(findings['session_cookies'][:3])}")

        # API key header hints
        if findings.get("api_key_header_hints"):
            _add("apikey_header", 45,
                 f"API key headers: {', '.join(findings['api_key_header_hints'][:2])}")

        # API key cookie hints
        if findings.get("apikey_cookie_hints"):
            _add("apikey_cookie", 55,
                 f"API key cookies: {', '.join(findings['apikey_cookie_hints'][:2])}")

        # API key validated via cookie
        for vr in findings.get("validation_results", []):
            if vr.get("method") == "apikey_cookie" and vr.get("success"):
                _add("apikey_cookie", 40, "API key cookie validation succeeded")
            elif vr.get("method") == "apikey_header" and vr.get("success"):
                _add("apikey_header", 40, "API key header validation succeeded")

        # Well-known endpoints
        if "openid_configuration" in well_known:
            _add("oidc_token", 60, "OpenID Connect config found")
            _add("oauth2_client_creds", 50, "OIDC implies OAuth2")
        if any(k in well_known for k in ("openapi_json", "swagger_json", "v3_api_docs")):
            spec = well_known.get("openapi_json") or well_known.get("swagger_json") or {}
            snip = spec.get("body_snip", "")
            if '"bearer"' in snip.lower() or '"jwt"' in snip.lower():
                _add("bearer", 50, "OpenAPI spec references Bearer security")
            if '"apikey"' in snip.lower():
                _add("apikey_header", 50, "OpenAPI spec references API key")
            if '"oauth2"' in snip.lower():
                _add("oauth2_client_creds", 50, "OpenAPI spec references OAuth2")
        if "graphql" in well_known:
            _add("bearer", 40, "GraphQL endpoint found; Bearer is conventional")
            _add("apikey_header", 30, "GraphQL may use API key header")

        # Software fingerprint hints
        for sw in sw_matches[:2]:
            for m in sw.get("auth_hints", []):
                delta = max(20, sw["confidence"] // 2)
                _add(m, delta, f"{sw['name']} fingerprint (conf {sw['confidence']}%)")

        # Default fallbacks
        url_type = findings.get("url_type", "unknown")
        if not scores:
            if url_type == "api":
                _add("bearer", 30, "API default")
                _add("apikey_header", 20, "API default")
            elif url_type == "webapp":
                _add("form_login", 30, "Webapp default")
                _add("basic", 15, "Webapp fallback")

        result = []
        for method, data in sorted(scores.items(),
                                   key=lambda x: x[1]["confidence"],
                                   reverse=True):
            notes = "; ".join(data["signals"][:3])
            result.append({
                "method":     method,
                "confidence": data["confidence"],
                "notes":      notes,
                "signals":    data["signals"],
            })
        return result

    def _error(self, url: str, msg: str) -> dict:
        return {
            "url":                  url,
            "url_type":             "unknown",
            "url_type_confidence":  0,
            "auth_methods":         [],
            "software":             [],
            "recommendations":      [],
            "findings":             {"error": msg},
        }


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    _console.log(f"AuthProbe v{VERSION} starting", "INFO")
    _console.status("init", label="AuthProbe", status="running", step="Initializing")
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="authprobe.py",
        description="AuthProbe — Detect & probe authentication methods on web apps and APIs",
    )
    parser.add_argument("--url",        metavar="URL",    required=True,
                        help="Target URL (can be root, a login endpoint, or a protected path)")
    parser.add_argument("--type",       metavar="TYPE",   default="auto",
                        choices=["auto", "webapp", "api"],
                        help="Target type: auto (default), webapp, or api")
    parser.add_argument("--username",   metavar="USER",   default="",
                        help="Username for credential validation")
    parser.add_argument("--password",   metavar="PASS",   default="",
                        help="Password for credential validation")
    parser.add_argument("--token",      metavar="TOKEN",  default="",
                        help="Bearer token for credential validation")
    parser.add_argument("--api-key",    metavar="KEY",    default="",
                        help="API key value for apikey_header / apikey_cookie validation")
    parser.add_argument("--api-key-header", metavar="HEADER", default="X-API-Key",
                        help="Header name for API key (default: X-API-Key)")
    parser.add_argument("--api-key-cookie", metavar="COOKIE", default="api_key",
                        help="Cookie name for API key (default: api_key)")
    parser.add_argument("--login-url",   metavar="URL",    default="",
                        help="Explicit login endpoint URL for credential validation (overrides discovery)")
    parser.add_argument("--totp-secret", metavar="SECRET", default="",
                        help="Base32 TOTP secret — auto-completes MFA challenge after valid credentials")
    parser.add_argument("--proxy",      metavar="PROXY",  default="",
                        help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--timeout",    metavar="SEC",    type=int, default=10,
                        help="Request timeout in seconds")
    parser.add_argument("--json",       action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--no-verify",  action="store_true",
                        help="Disable SSL verification (already disabled by default)")
    parser.add_argument("--rendered",   action="store_true",
                        help="Render page with headless Chrome (Selenium) for SPA fingerprinting")
    parser.add_argument("--driver-path", metavar="PATH", default="",
                        help="Path to ChromeDriver binary (auto-detected if omitted)")
    parser.add_argument("--output-dir",  metavar="DIR",  default="",
                        help="Write meta.json + findings.json + summary.json (schema 1.0) "
                             "to DIR for ingestion by Prometheus / pr0t31n consumers.")
    parser.add_argument("--client-short",    metavar="SLUG", default="",
                        help="Client short identifier for meta.json (used with --output-dir).")
    parser.add_argument("--client-name",     metavar="NAME", default="",
                        help="Client full name for meta.json (used with --output-dir).")
    parser.add_argument("--engagement-name", metavar="NAME", default="",
                        help="Engagement name for meta.json (used with --output-dir).")
    parser.add_argument("--build-session", action="store_true",
                        help="Build an authenticated session and test connectivity "
                             "(requires --auth-method and credentials)")
    parser.add_argument("--auth-method",   metavar="METHOD", default="",
                        help="Auth method for --build-session (e.g. form_login, basic, "
                             "bearer, token_login, auto). Use --list-methods to see all.")
    parser.add_argument("--login-mode",    metavar="MODE",  default="fields",
                        choices=["fields", "json", "merge"],
                        help="Login POST mode: fields (form-encoded, default), json, merge")
    parser.add_argument("--login-username-field", metavar="FIELD", default="username",
                        help="Form field name for username (default: username)")
    parser.add_argument("--login-password-field", metavar="FIELD", default="password",
                        help="Form field name for password (default: password)")
    parser.add_argument("--login-token-path", metavar="PATH", default="token",
                        help="Dot-path to extract token from JSON response (e.g. data.access_token)")
    parser.add_argument("--login-content-type", metavar="CT", default="application/json",
                        help="Content-Type for login POST (default: application/json)")
    parser.add_argument("--session-cookie", metavar="COOKIES", default="",
                        help="Pre-captured session cookie string for session_cookie method")
    parser.add_argument("--domain",        metavar="DOMAIN", default="",
                        help="AD domain for NTLM auth (e.g. CORP)")
    parser.add_argument("--list-methods",  action="store_true",
                        help="List all supported auth methods and exit")
    args = parser.parse_args()

    # ── --list-methods: print all auth methods and exit ──
    if args.list_methods:
        print(f"\nAuthProbe v{VERSION} — Supported Authentication Methods\n")
        for method, desc in AUTH_METHODS.items():
            print(f"  {method:24s}  {desc}")
        print(f"\n  {len(AUTH_METHODS)} methods supported.\n")
        sys.exit(0)

    # ── --build-session: test authenticated connectivity ──
    if args.build_session:
        method = args.auth_method
        if not method:
            print("ERROR: --build-session requires --auth-method")
            sys.exit(1)
        if method not in AUTH_METHODS:
            print(f"ERROR: unknown auth method '{method}'. Use --list-methods to see all.")
            sys.exit(1)
        auth_cfg = {
            "method":               method,
            "username":             args.username,
            "password":             args.password,
            "auth_token":           args.token,
            "login_url":            args.login_url or args.url,
            "login_mode":           args.login_mode,
            "login_username_field": args.login_username_field,
            "login_password_field": args.login_password_field,
            "login_token_path":     args.login_token_path,
            "login_content_type":   args.login_content_type,
            "api_key":              args.api_key,
            "api_key_header":       args.api_key_header,
            "api_key_cookie":       args.api_key_cookie,
            "totp_secret":          args.totp_secret,
            "session_cookie":       args.session_cookie,
            "domain":               args.domain,
            "_target_url":          args.url,
        }
        _console.log(f"Building auth session: method={method}", "INFO")
        _console.status("build-session", label="AuthProbe",
                        status="running", step=f"Auth: {method}")
        sess, info = build_auth_session(
            auth_cfg,
            timeout=args.timeout,
            proxy=args.proxy,
            verify_ssl=not args.no_verify,
        )
        failed = info.startswith("ERROR:")
        if failed:
            _console.error(info)
        else:
            _console.log(info, "SUCCESS")
            # Probe the target with the authenticated session
            _console.log(f"Probing {args.url} with authenticated session...", "INFO")
            try:
                resp = sess.get(args.url, timeout=args.timeout)
                sc = resp.status_code
                _console.log(f"Authenticated GET {args.url} → HTTP {sc}", "SUCCESS")
                info += f" | GET {args.url} → HTTP {sc}"
                if sc in (401, 403):
                    failed = True
                    info = f"ERROR: authenticated GET → HTTP {sc} — auth may have failed"
            except Exception as exc:
                info += f" | GET failed: {exc}"

        result = {
            "success": not failed,
            "message": info,
            "method":  method,
            "url":     args.url,
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            icon = green("✓") if not failed else red("✗")
            print(f"\n  {icon}  {bold(method)}")
            print(f"       {info}")
        _console.status("build-session", label="AuthProbe",
                        status="complete" if not failed else "error",
                        step="Done")
        sys.exit(0 if not failed else 1)

    global _PAUSE
    if _pp is not None and args.output_dir:
        import os
        _PAUSE = _pp.PauseManager(args.output_dir, "authprobe")
        _PAUSE.start_watcher(grace_period=60)
        _resumed = os.environ.get("CRUCIBLE_RESUME") == "1"
        _PAUSE.log_run_type(resumed=_resumed)

    raw_url = args.url.rstrip("/")
    parsed  = urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "https://" + raw_url
        parsed  = urlparse(raw_url)

    origin, url_path, full_url = _split_url(raw_url)
    given_is_login_path = _is_login_path(url_path)
    probe_root          = origin if given_is_login_path else full_url
    direct_login_url    = full_url if given_is_login_path else None
    skip_paths: set = {url_path.rstrip("/")} if given_is_login_path else set()

    # Auto-detect type
    probe_type = args.type
    if probe_type == "auto":
        path_lc = url_path.lower()
        if re.search(r'/api/|/v\d+/', path_lc) or "api." in parsed.netloc.lower():
            probe_type = "api"
        else:
            probe_type = "webapp"

    _console.log(f"Target: {full_url} | Origin: {origin} | Mode: {probe_type}", "INFO")
    if given_is_login_path:
        _console.log("Provided URL appears to be a login endpoint — probing directly", "WARNING")
    print(f"  {dim('Target :')} {cyan(full_url)}")
    print(f"  {dim('Origin :')} {cyan(origin)}")
    print(f"  {dim('Mode   :')} {cyan(probe_type)}")
    if given_is_login_path:
        print(f"  {dim('Note   :')} {yellow('Provided URL appears to be a login endpoint — probing directly')}")
    print()

    findings: dict = {
        "www_authenticate":      [],
        "form_login":            False,
        "form_login_evidence":   [],
        "json_api_auth":         False,
        "json_api_auth_url":     "",
        "json_api_cred_checked": False,
        "token_login_likely":    False,
        "token_login_url":       "",
        "oauth_discovery":       [],
        "session_cookies":       [],
        "api_key_header_hints":  [],
        "login_endpoints":       [],
        "security_headers":      {},
        "basic_auth":            None,
        "ntlm_detected":         False,
        "kerberos_detected":     False,
        "validation_results":    [],
        "software_matches":      [],
        "well_known":            {},
        "url_type":              "unknown",
        "url_type_confidence":   0,
    }

    # Phase 1: Probe the provided URL
    _console.log(f"[Phase 1/5] Probing target URL: {full_url}", "INFO")
    _console.status("probe", label="AuthProbe", status="running",
                    step="Probing target URL", progress=1, total=5)
    print(f"  {dim('[1/5]')} Probing target URL…")
    base_resp = _safe_get(sess := _make_session(args), full_url, args.timeout)

    body = ""
    try:
        body = (base_resp.text if base_resp is not None else "")[:8000]
    except Exception:
        pass

    if base_resp is None:
        _console.error(f"All HTTP probes to {full_url} failed (network/timeout)")
    else:
        _console.log(f"[Phase 1/5] Target responded: HTTP {base_resp.status_code}", "SUCCESS")

    detect_www_authenticate(base_resp, findings)
    detect_basic_auth(base_resp, findings)
    detect_ntlm_kerberos(base_resp, findings)
    detect_form_login(base_resp, findings)
    detect_json_api_auth(base_resp, full_url, findings)
    detect_token_login_response(base_resp, full_url, findings)
    detect_session_cookies(base_resp, findings)
    detect_security_headers(base_resp, findings)

    if findings.get("www_authenticate"):
        _console.log(f"[Phase 1/5] Detected WWW-Authenticate: {[e['scheme'] for e in findings['www_authenticate']]}", "SUCCESS")
    if findings.get("basic_auth") is not None:
        _console.log(f"[Phase 1/5] Detected HTTP Basic Auth (realm={findings['basic_auth'].get('realm', '')})", "SUCCESS")
    if findings.get("ntlm_detected"):
        _console.log("[Phase 1/5] Detected NTLM authentication", "SUCCESS")
    if findings.get("kerberos_detected"):
        _console.log("[Phase 1/5] Detected Kerberos/SPNEGO authentication", "SUCCESS")
    if findings.get("form_login"):
        _console.log(f"[Phase 1/5] Detected HTML form-based login ({len(findings.get('form_login_evidence', []))} pattern(s))", "SUCCESS")
    if findings.get("json_api_auth"):
        _console.log(f"[Phase 1/5] Detected JSON API auth endpoint: {findings.get('json_api_auth_url', '')}", "SUCCESS")
    if findings.get("session_cookies"):
        _console.log(f"[Phase 1/5] Session cookies: {', '.join(findings['session_cookies'][:5])}", "INFO")
    if findings.get("security_headers"):
        _console.log(f"[Phase 1/5] Security headers present: {', '.join(findings['security_headers'].keys())}", "INFO")
    _console.log("[Phase 1/5] Initial probe detection — completed", "SUCCESS")

    if given_is_login_path:
        findings["login_endpoints"].append({
            "path": url_path,
            "status": base_resp.status_code if base_resp is not None else 0,
            "content_type": base_resp.headers.get("Content-Type", "")[:60] if base_resp is not None else "",
        })

    # Phase 2: Software fingerprinting (static HTML)
    _console.log(f"[Phase 2/5] Fingerprinting software against {full_url}...", "INFO")
    _console.status("fingerprint", label="AuthProbe", status="running",
                    step="Software fingerprinting", progress=2, total=5)
    print(f"  {dim('[2/5]')} Fingerprinting software…")
    cookie_names = [c.name for c in (base_resp.cookies if base_resp is not None else [])]
    sw_matches = fingerprint_software(
        full_url, dict(base_resp.headers if base_resp is not None else {}), body, cookie_names
    )

    if getattr(args, "rendered", False):
        _console.log("[Phase 2b/5] Rendering page in headless Chrome for SPA fingerprinting...", "INFO")
        print(f"  {dim('[2b/5]')} Rendering page (headless Chrome)…")
        rendered_result = fingerprint_rendered(
            full_url,
            timeout=args.timeout + 5,
            proxy=args.proxy,
            driver_path=getattr(args, "driver_path", ""),
        )
        if rendered_result.get("error"):
            _console.log(f"[Phase 2b/5] Rendered analysis failed: {rendered_result['error']}", "WARNING")
            print(f"          {yellow('!')} Rendered analysis: {rendered_result['error']}")
        else:
            r_title   = rendered_result.get("title", "")
            r_signals = rendered_result.get("dom_signals", [])
            if r_title:
                print(f"          → Page title: {cyan(r_title)}")
            for sig in r_signals:
                print(f"          → {dim(sig)}")
            # Merge rendered software matches
            existing_names = {m["name"] for m in sw_matches}
            for rm in rendered_result.get("software_matches", []):
                if rm["name"] not in existing_names:
                    sw_matches.append(rm)
                    existing_names.add(rm["name"])
                else:
                    for m in sw_matches:
                        if m["name"] == rm["name"]:
                            m["confidence"] = min(m["confidence"] + 20, 95)
                            m["indicators"] += [
                                f"[rendered] {s}" for s in rm.get("indicators", [])
                            ]
            # Re-check form login in rendered HTML
            rendered_body = (
                rendered_result.get("rendered_html", "")
                + "\n" + rendered_result.get("visible_text", "")
            )
            if rendered_body.strip():
                detect_form_login(
                    type("_FakeResp", (), {
                        "status_code": 200,
                        "headers": {"Content-Type": "text/html"},
                        "text": rendered_body,
                    })(),
                    findings,
                )
        sw_matches.sort(key=lambda x: x["confidence"], reverse=True)

    findings["software_matches"] = sw_matches
    if sw_matches:
        _console.log(f"[Phase 2/5] Identified software: {', '.join(sw['name'] for sw in sw_matches[:3])}", "SUCCESS")
        print(f"          → Identified: {', '.join(sw['name'] for sw in sw_matches[:3])}")
    else:
        _console.log("[Phase 2/5] No software fingerprints matched", "INFO")

    # Phase 3: Well-known / spec endpoint discovery
    _console.log(f"[Phase 3/5] Probing well-known endpoints on {origin}...", "INFO")
    _console.status("well-known", label="AuthProbe", status="running",
                    step="Well-known endpoint discovery", progress=3, total=5)
    print(f"  {dim('[3/5]')} Probing well-known endpoints…")
    well_known = probe_well_known(sess, full_url, args.timeout)
    findings["well_known"] = well_known
    if well_known:
        _console.log(f"[Phase 3/5] Found well-known endpoints: {', '.join(well_known.keys())}", "SUCCESS")
        print(f"          → Found: {', '.join(well_known.keys())}")
    else:
        _console.log("[Phase 3/5] No well-known endpoints responded", "INFO")

    # Phase 3b: /auth-info hint parsing (DV apps and compatible targets)
    _console.log("[Phase 3b/5] Checking /auth-info endpoint...", "INFO")
    _ai = well_known.get("auth_info", {})
    if _ai.get("status_code") == 200:
        try:
            _ai_resp = _safe_get(sess, _ai["url"], args.timeout)
            if _ai_resp is not None:
                _ai_body = _ai_resp.json()
                _ai_mode = _ai_body.get("auth_mode", "")
                # Auth details are nested inside siphon_settings or fracture_settings
                _ai_auth = (
                    _ai_body.get("siphon_settings", {}).get("scan", {}).get("auth", {}) or
                    _ai_body.get("fracture_settings", {}).get("scan", {}).get("auth", {})
                )
                if _ai_mode:
                    _console.log(f"[Phase 3b/5] Found auth_info_mode: {_ai_mode}", "SUCCESS")
                    findings["auth_info_mode"] = _ai_mode
                    if _ai_mode == "basic" and findings.get("basic_auth") is None:
                        findings["basic_auth"] = {"realm": ""}
                    if _ai_mode == "totp_mfa":
                        _ts = _ai_auth.get("totp_secret", "")
                        _tf = _ai_auth.get("totp_field", "otp")
                        if _ts:
                            findings["auth_info_totp_secret"] = _ts
                            findings["auth_info_totp_field"]  = _tf
                    # jwt_bearer: app may provide a pre-issued token in auth config
                    if _ai_mode == "jwt_bearer":
                        _pre_token = _ai_auth.get("auth_token", "").strip()
                        if _pre_token:
                            findings["auth_info_jwt_token"] = _pre_token
                _ai_login_url = (_ai_auth.get("login_url") or
                                 _ai_auth.get("oauth_token_url") or "")
                if _ai_login_url:
                    findings["auth_info_login_url"] = _ai_login_url
        except Exception:
            pass

    # Phase 4: URL type classification
    _console.log("[Phase 4/5] Classifying URL type...", "INFO")
    # When --type was explicitly specified (not "auto"), trust it directly.
    if args.type != "auto":
        url_type      = args.type
        url_type_conf = 99
    else:
        url_type, url_type_conf = classify_url_type(
            full_url, base_resp, body, well_known, sw_matches
        )
    findings["url_type"]            = url_type
    findings["url_type_confidence"] = url_type_conf
    _console.log(f"[Phase 4/5] URL type: {url_type} ({url_type_conf}% confidence)", "SUCCESS")
    colour = green if url_type_conf >= 60 else yellow
    print(f"          → URL type: {colour(url_type)} ({url_type_conf}% confidence)")

    # Phase 5: Login endpoint discovery + OAuth/OIDC
    _console.log(f"[Phase 5a/5] Probing login endpoints from {origin}...", "INFO")
    _console.status("login-discovery", label="AuthProbe", status="running",
                    step="Login endpoint discovery", progress=4, total=5)
    print(f"  {dim('[4/5]')} Probing login endpoints from origin…")
    if given_is_login_path:
        root_resp = _safe_get(sess, origin, args.timeout)
        if root_resp is not None:
            detect_www_authenticate(root_resp, findings)
            detect_basic_auth(root_resp, findings)
            detect_ntlm_kerberos(root_resp, findings)
            detect_form_login(root_resp, findings)
            detect_session_cookies(root_resp, findings)
    detect_login_endpoints(sess, origin, args.timeout, probe_type, skip_paths, findings)

    if findings.get("login_endpoints"):
        _console.log(f"[Phase 5a/5] Found {len(findings['login_endpoints'])} login endpoint(s): "
                     f"{', '.join(ep['path'] for ep in findings['login_endpoints'][:5])}", "SUCCESS")
    else:
        _console.log("[Phase 5a/5] No login endpoints discovered", "INFO")

    _console.log("[Phase 5b/5] Checking OAuth/OIDC discovery...", "INFO")
    _console.status("oauth", label="AuthProbe", status="running",
                    step="OAuth/OIDC discovery", progress=5, total=5)
    print(f"  {dim('[5/5]')} Checking OAuth/OIDC discovery…")
    detect_oauth_discovery(sess, origin, args.timeout, findings)
    if findings.get("oauth_discovery"):
        _console.log(f"[Phase 5b/5] Found OAuth/OIDC configuration: "
                     f"{findings['oauth_discovery'][0].get('issuer', '?')}", "SUCCESS")
    else:
        _console.log("[Phase 5b/5] No OAuth/OIDC discovery endpoints found", "INFO")

    # Credential validation
    _auth_success = False  # initialised here so protocol-specific blocks below are always valid
    if args.username and args.password:
        _console.log(f"[Validation] Testing credentials for {args.username} against {full_url}...", "INFO")
        _console.status("validation", label="AuthProbe", status="running",
                        step="Credential validation")
        print(f"  {dim('[+]')} Credential validation…")

        login_targets = []
        if direct_login_url:
            login_targets.append(direct_login_url)
        # Prefer /auth-info reported login URL — highest fidelity
        _ai_login_url = findings.get("auth_info_login_url", "")
        if _ai_login_url and _ai_login_url not in login_targets:
            login_targets.insert(0, _ai_login_url)
        # Explicit --login-url overrides everything — insert at very front
        _explicit_login_url = getattr(args, "login_url", "").strip()
        if _explicit_login_url and _explicit_login_url not in login_targets:
            login_targets.insert(0, _explicit_login_url)
        for ep in findings.get("login_endpoints", []):
            ep_url = origin.rstrip("/") + ep["path"]
            if ep_url not in login_targets and ep["status"] in (200, 400, 401, 403, 405, 422):
                login_targets.append(ep_url)

        # jwt_bearer with pre-issued token — validate by making an authenticated request
        _ai_jwt_token = findings.get("auth_info_jwt_token", "") or getattr(args, "token", "")
        if findings.get("auth_info_mode") == "jwt_bearer" and _ai_jwt_token:
            _console.log("[Validation] Found pre-issued JWT token — testing bearer auth...", "INFO")
            _jwt_probe_paths = ["/api/users", "/api/me", "/users", "/me",
                                "/api/items", "/profile", "/api/data", "/api/admin"]
            _jwt_ok = False
            for _jp in _jwt_probe_paths:
                try:
                    _jr = sess.get(
                        origin.rstrip("/") + _jp,
                        headers={"Authorization": f"Bearer {_ai_jwt_token}",
                                 "Accept": "application/json"},
                        timeout=args.timeout,
                    )
                    if _jr.status_code not in (404, 405):
                        findings["validation_results"].append({
                            "method":   "jwt_bearer",
                            "success":  _jr.status_code not in (401, 403),
                            "status":   _jr.status_code,
                            "evidence": (
                                f"Pre-issued JWT tested against {_jp} → HTTP {_jr.status_code}"
                            ),
                        })
                        if _jr.status_code not in (401, 403):
                            findings["token_login_likely"] = True
                            findings["token_login_url"]    = login_targets[0] if login_targets else ""
                            _auth_success = True
                        _jwt_ok = True
                        break
                except Exception:
                    continue
            if not _jwt_ok:
                findings["validation_results"].append({
                    "method":   "jwt_bearer",
                    "success":  True,
                    "status":   None,
                    "evidence": "Pre-issued JWT token present (could not probe endpoint to confirm)",
                })
                findings["token_login_likely"] = True
                _auth_success = True

        # Single-step TOTP — OTP included in the initial credential POST.
        # Used when /auth-info reports totp_mfa and provides the secret, or --totp-secret
        # was passed directly. Bypasses the two-step challenge flow which requires a
        # separate OTP submission endpoint that not all apps implement.
        _ai_totp_secret = findings.get("auth_info_totp_secret", "") or getattr(args, "totp_secret", "")
        _ai_totp_field  = findings.get("auth_info_totp_field",  "otp")
        if (findings.get("auth_info_mode") == "totp_mfa" and
                _ai_totp_secret and login_targets):
            _console.log("[Validation] TOTP MFA mode detected — attempting single-step login...", "INFO")
            _totp_code = _generate_totp(_ai_totp_secret)
            if _totp_code:
                _totp_done = False
                for _lt in login_targets[:3]:
                    if _totp_done:
                        break
                    for _uf, _pf in _CRED_FIELD_COMBOS:
                        _payload = {
                            _uf: args.username,
                            _pf: args.password,
                            _ai_totp_field: _totp_code,
                        }
                        _r = _safe_post(sess, _lt, args.timeout,
                                        json=_payload,
                                        headers={"Content-Type": "application/json",
                                                 "Accept": "application/json"})
                        if _r is not None and _r.status_code in (200, 201):
                            _body = _json_body(_r)
                            if isinstance(_body, dict):
                                _matched = (_nested_keys(_body) &
                                            {k.lower() for k in _TOKEN_RESPONSE_KEYS})
                                if _matched:
                                    findings["validation_results"].append({
                                        "method":   "totp_mfa",
                                        "success":  True,
                                        "status":   _r.status_code,
                                        "evidence": (
                                            f"Single-step TOTP login succeeded "
                                            f"(field combo: {_uf}/{_pf}, "
                                            f"otp_field: {_ai_totp_field}, "
                                            f"token keys: {_matched})"
                                        ),
                                    })
                                    findings["token_login_likely"] = True
                                    findings["token_login_url"]    = _lt
                                    _auth_success = True
                                    _totp_done = True
                                    break

        _non_form_auth_modes = {
            "basic", "digest", "ntlm", "ntlm_v2", "bearer", "jwt_bearer",
            "kerberos", "oauth2_client_creds", "oauth1a", "saml_assertion",
            "oidc_token", "mtls", "webauthn_probe",
        }

        # ── form_login — tested FIRST when detected ───────────────────────────
        # Builds its own target list: login_targets (honours --login-url) first,
        # then any discovered endpoints not already in the list.
        if (not _auth_success and
                findings.get("form_login") and
                findings.get("auth_info_mode", "") not in _non_form_auth_modes):
            _console.log("[Validation] Form login detected — testing credentials...", "INFO")
            _form_targets = list(login_targets)
            for ep in findings.get("login_endpoints", []):
                ep_url = origin.rstrip("/") + ep["path"]
                if ep_url not in _form_targets and ep["status"] in (200, 302):
                    _form_targets.append(ep_url)
            for ft in _form_targets[:3]:
                result = validate_form_login(sess, ft, args.username, args.password, args.timeout)
                findings["validation_results"].append(result)
                if result.get("success"):
                    _console.log(f"[Validation] Form login succeeded against {ft}", "SUCCESS")
                    findings["form_login_confirmed_url"] = ft
                    _auth_success = True
                    break

        # ── token_login — only if form_login did not succeed ──────────────────
        if not _auth_success:
            _console.log("[Validation] Testing token/API login...", "INFO")
            for lt in login_targets[:3]:
                result = validate_token_login(sess, lt, args.username, args.password, args.timeout)
                findings["validation_results"].append(result)
                if result.get("success") or result.get("endpoint_confirmed"):
                    if result.get("success") and not result.get("mfa_required"):
                        findings["token_login_likely"] = True
                        findings["token_login_url"]    = lt
                        _auth_success = True
                    elif result.get("mfa_required"):
                        _console.log(f"[Validation] Credentials accepted — MFA challenge issued (types: {result.get('mfa_types', [])})", "SUCCESS")
                        findings["token_login_likely"] = True
                        findings["token_login_url"]    = lt
                        findings["mfa_required"]       = True
                        findings["mfa_types"]          = result.get("mfa_types", [])
                        _auth_success = True
                        totp_secret = getattr(args, "totp_secret", "").strip()
                        if totp_secret and "totp" in [t.lower() for t in result.get("mfa_types", [])]:
                            totp_code = _generate_totp(totp_secret)
                            if totp_code:
                                _console.log("[Validation] Found TOTP in MFA types — completing TOTP challenge...", "INFO")
                                print(f"  {dim('[+]')} Completing TOTP MFA challenge…")
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
                        elif not args.json:
                            mfa_types_str = ", ".join(result.get("mfa_types", [])) or "unknown"
                            print(f"\n  {yellow('MFA challenge received')}  [{mfa_types_str}]")
                            try:
                                totp_code = input(f"  Enter TOTP code: ").strip()
                            except (EOFError, KeyboardInterrupt):
                                totp_code = ""
                            if totp_code:
                                _console.log("[Validation] Submitting user-provided TOTP code...", "INFO")
                                print(f"  {dim('[+]')} Submitting TOTP code…")
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
                        findings["json_api_auth"]         = True
                        findings["json_api_auth_url"]     = lt
                        findings["json_api_cred_checked"] = True
                    break

        # ── basic_auth — only if no method has succeeded yet ─────────────────
        if not _auth_success and findings.get("basic_auth") is not None:
            _console.log("[Validation] Testing HTTP Basic auth credentials...", "INFO")
            result = validate_basic(sess, full_url, args.username, args.password, args.timeout)
            findings["validation_results"].append(result)
            if result.get("success"):
                _console.log("[Validation] HTTP Basic auth credentials — valid", "SUCCESS")
                _auth_success = True
            else:
                _console.log("[Validation] HTTP Basic auth credentials — failed", "WARNING")

    # ── Protocol-specific credential validation ───────────────────────────────
    _ai_mode_v = findings.get("auth_info_mode", "")
    _val_probe_paths = ["/", "/users", "/users/", "/api/users", "/api/users/",
                        "/dashboard", "/dashboard/", "/home", "/home/", "/profile/"]

    # Digest — only if no method has already succeeded
    if (not _auth_success and
            (_ai_mode_v == "digest" or
             any(e.get("scheme", "").lower() == "digest"
                 for e in findings.get("www_authenticate", [])))):
        _console.log("[Validation] Testing Digest auth credentials...", "INFO")
        from requests.auth import HTTPDigestAuth
        _d_auth = HTTPDigestAuth(args.username, args.password)
        _d_added = False
        for _dp in _val_probe_paths:
            _dr = _safe_get(sess, origin.rstrip("/") + _dp, args.timeout, auth=_d_auth)
            if _dr is not None and _dr.status_code not in (404, 405):
                findings["validation_results"].append({
                    "method":   "digest",
                    "success":  _dr.status_code not in (401, 403),
                    "status":   _dr.status_code,
                    "evidence": f"Digest GET {_dp} → HTTP {_dr.status_code}",
                })
                _d_added = True
                break
        if not _d_added:
            findings["validation_results"].append({
                "method":   "digest",
                "success":  None,
                "status":   None,
                "evidence": "Digest auth detected but no probe endpoint responded",
            })

    # NTLM / NTLMv2 — only if no method has already succeeded
    if (not _auth_success and
            (_ai_mode_v in ("ntlm", "ntlm_v2") or findings.get("ntlm_detected"))):
        _console.log("[Validation] Testing NTLM credentials...", "INFO")
        try:
            from requests_ntlm import HttpNtlmAuth
            _n_auth = HttpNtlmAuth(args.username, args.password)
            _n_added = False
            for _np in _val_probe_paths:
                _nr = _safe_get(sess, origin.rstrip("/") + _np, args.timeout, auth=_n_auth)
                if _nr is not None and _nr.status_code not in (404, 405):
                    _n_ok = _nr.status_code not in (401, 403)
                    # 401 after NTLM probe means either wrong creds OR server doesn't
                    # support proper NTLM handshake (simplified prefix-check servers).
                    # Report None (unverifiable) rather than False to avoid false negatives.
                    if not _n_ok:
                        _n_ok = None
                    findings["validation_results"].append({
                        "method":   _ai_mode_v or "ntlm",
                        "success":  _n_ok,
                        "status":   _nr.status_code,
                        "evidence": f"NTLM GET {_np} → HTTP {_nr.status_code}",
                    })
                    _n_added = True
                    break
            if not _n_added:
                findings["validation_results"].append({
                    "method":   _ai_mode_v or "ntlm",
                    "success":  None,
                    "status":   None,
                    "evidence": "NTLM auth attempted but no probe endpoint responded",
                })
        except ImportError:
            findings["validation_results"].append({
                "method":   _ai_mode_v or "ntlm",
                "success":  None,
                "status":   None,
                "evidence": "requests_ntlm not installed — NTLM credentials not verifiable",
            })

    # Kerberos / SPNEGO
    if (_ai_mode_v in ("kerberos", "kerberos_delegation") or findings.get("kerberos_detected")):
        _console.log("[Validation] Kerberos/SPNEGO detected — not verifiable locally", "WARNING")
        findings["validation_results"].append({
            "method":   _ai_mode_v or "kerberos",
            "success":  None,
            "status":   None,
            "evidence": "Kerberos requires kinit + requests-kerberos — not verifiable locally",
        })

    if args.token:
        _console.log("[Validation] Testing Bearer token...", "INFO")
        findings["validation_results"].append(
            validate_bearer(sess, full_url, args.token, args.timeout))

    if args.api_key:
        _console.log("[Validation] Testing API key (cookie + header)...", "INFO")
        findings["validation_results"].append(
            validate_apikey_cookie(sess, full_url, args.api_key,
                                   args.api_key_cookie, args.timeout))
        findings["validation_results"].append(
            validate_apikey_header(sess, full_url, args.api_key,
                                   args.api_key_header, args.timeout))

    # ── Login profile store check ─────────────────────────────────────────────
    # Run only when the target looks like a web login page (form_login detected
    # or html URL type) so we don't waste a GET against pure API endpoints.
    _lp_candidate = None
    if findings.get("form_login") or findings.get("url_type") == "webapp":
        _console.log("[Profile] Checking Fracture login profile store for structural match...", "INFO")
        try:
            _lp_candidate = _lp_match_from_index(full_url)
            if _lp_candidate:
                _console.log(f"[Profile] Found matching login profile: {_lp_candidate.get('id', '?')} "
                             f"(confidence: {_lp_candidate.get('confidence', 0)}%)", "SUCCESS")
                findings["login_profile_match"] = _lp_candidate
        except Exception:
            pass

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, args)
        print(f"\n{dim('─' * 60)}")
        print(f"  {dim('AuthProbe v' + VERSION + ' complete')}")
        print()

    _console.log(f"AuthProbe v{VERSION} probe complete for {full_url}", "SUCCESS")
    _console.status("complete", label="AuthProbe", status="completed",
                    step="Probe finished")

    if _PAUSE:
        _PAUSE.write_stop_reason("completed", "probe_finished")

    # ── Universal output dir (schema 1.0) ─────────────────────────────────
    if args.output_dir:
        _write_universal_output(args.output_dir, full_url, findings, args)


def _write_universal_output(out_dir_str: str, target_url: str,
                            findings: dict, args) -> None:
    """Write meta.json + findings.json + summary.json (schema 1.0) to out_dir.
    Graceful no-op when /opt/pr0t31n/shared/pr0t31n_schema.py is not present."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_schema as _us
    except ImportError:
        _console.log("--output-dir given but pr0t31n_schema.py not installed — skipping universal output", "WARNING")
        print(f"  [!] --output-dir given but /opt/pr0t31n/shared/pr0t31n_schema.py "
              f"not installed — skipping universal output.")
        return

    out_dir = Path(out_dir_str).resolve()
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        _us.init_run_dir(out_dir)

        # meta.json
        _us.write_meta(out_dir, _us.make_meta(
            tool="authprobe", version=VERSION,
            client_short=args.client_short or "",
            client_name=args.client_name or args.client_short or "",
            engagement_name=args.engagement_name or f"authprobe {target_url}",
            target=target_url,
        ), legacy_filename=None)

        # findings.json — one finding per discrete observation, plus a
        # discovery-summary INFO finding holding the full JSON output.
        unified_findings = _authprobe_findings_to_universal(findings, target_url)
        (out_dir / "findings.json").write_text(
            json.dumps(unified_findings, indent=2), encoding="utf-8"
        )

        # summary.json
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in unified_findings:
            r = (f.get("risk") or "INFO").upper()
            if r in risk_counts:
                risk_counts[r] += 1
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _us.write_summary(out_dir, _us.make_summary(
            tool="authprobe", version=VERSION,
            scan_start=now_iso, scan_end=now_iso,
            target=target_url, success=True,
            total_findings=len(unified_findings),
            risk_counts=risk_counts,
        ))
        _console.log(f"Universal output written to {out_dir} ({len(unified_findings)} findings)", "SUCCESS")
        print(f"\n  {dim('Universal output:')} {cyan(str(out_dir))}")
        print(f"  {dim('  meta.json, findings.json (' + str(len(unified_findings)) + '), summary.json')}")
    except Exception as e:
        _console.error(f"--output-dir write failed: {e}")
        print(f"  [!] --output-dir write failed: {e}")


def _authprobe_findings_to_universal(findings: dict, target_url: str) -> list:
    """Convert AuthProbe's discovery dict into universal-schema finding entries."""
    try:
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(target_url)
        host = parsed.hostname or target_url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except Exception:
        host, port = target_url, 0

    out = []

    # 1. Discovery summary — always emitted, INFO level, contains full JSON.
    out.append({
        "id":          "",
        "tool":        "authprobe",
        "title":       f"AuthProbe Discovery: {host}",
        "datetime":    "",
        "ip":          host, "port": port, "hostname": host,
        "risk":        "INFO",
        "scope":       None, "phase": "", "catalogue_id": "",
        "command":     f"authprobe.py --url {target_url}",
        "description": ("Authentication and security-header discovery output. "
                        "AuthProbe identifies auth methods, software, and security "
                        "headers on the target. See 'output' for full JSON."),
        "output":      json.dumps(findings, indent=2)[:8192],
        "output_file": "", "cves": "",
        "sources":     "authprobe",
        "service":     "https" if port == 443 else "http",
        "affected":    target_url,
        "owasp":       "", "owasp_url": "", "nist": "",
        "remediation": ("Review discovered authentication mechanisms for weaknesses "
                        "(missing MFA, basic auth, deprecated mechanisms)."),
        "exploitdb":   False, "metasploit": False, "exploit_details": [],
    })

    # 2. Missing/weak security headers — one LOW finding per missing header.
    sec_headers = findings.get("security_headers") or {}
    EXPECTED = ["Strict-Transport-Security", "Content-Security-Policy",
                "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]
    for header in EXPECTED:
        if not sec_headers.get(header):
            out.append({
                "id": "", "tool": "authprobe",
                "title":       f"Missing Security Header: {header}",
                "datetime":    "",
                "ip": host, "port": port, "hostname": host,
                "risk": "LOW",
                "scope": None, "phase": "", "catalogue_id": "",
                "command":     f"authprobe.py --url {target_url}",
                "description": f"Response is missing the '{header}' security header, "
                               f"which mitigates a well-known attack class.",
                "output":      f"Headers seen: {', '.join(sec_headers.keys()) or '(none)'}",
                "output_file": "", "cves": "",
                "sources":     "authprobe",
                "service":     "https" if port == 443 else "http",
                "affected":    target_url,
                "owasp":       "A05:2021", "owasp_url": "",
                "nist":        "",
                "remediation": f"Add the '{header}' response header to all HTTP responses.",
                "exploitdb":   False, "metasploit": False, "exploit_details": [],
            })

    # 3. Basic Auth detected — MEDIUM (credentials over wire in base64).
    if findings.get("basic_auth"):
        out.append({
            "id": "", "tool": "authprobe",
            "title":       "HTTP Basic Authentication in Use",
            "datetime":    "",
            "ip": host, "port": port, "hostname": host,
            "risk": "MEDIUM",
            "scope": None, "phase": "", "catalogue_id": "",
            "command":     f"authprobe.py --url {target_url}",
            "description": "Server presents HTTP Basic auth. Credentials are sent "
                           "base64-encoded with every request — trivially decoded.",
            "output":      json.dumps(findings.get("basic_auth"), indent=2),
            "output_file": "", "cves": "",
            "sources":     "authprobe",
            "service":     "https" if port == 443 else "http",
            "affected":    target_url,
            "owasp":       "A07:2021", "owasp_url": "",
            "nist":        "",
            "remediation": "Replace Basic auth with token-based authentication "
                           "(OAuth2, JWT) or session-cookie + MFA.",
            "exploitdb":   False, "metasploit": False, "exploit_details": [],
        })

    return out


if __name__ == "__main__":
    main()

# AuthProbe

Authentication detection and probing tool for web applications and APIs. Identifies authentication methods, fingerprints software platforms, discovers login endpoints, and optionally validates credentials — all from a single URL.

## Features

- **8-phase probe pipeline**: primary URL → auth signal detection → software fingerprinting → well-known endpoint discovery → URL type classification → JS bundle mining + SPA detection → login endpoint discovery → confidence-scored recommendations
- **42 software fingerprints**: WordPress, Joomla, Drupal, Jenkins, GitLab, Grafana, Kibana, Okta, Keycloak, ADFS, Azure AD, Palo Alto PAN-OS, Fortinet, Cisco ASA, F5 BIG-IP, Kong, AWS API Gateway, Kubernetes API, Ubiquiti (UniFi/AirOS/UISP/EdgeOS), and more
- **21 auth methods** for session building and credential validation: form_login, basic, digest, ntlm, ntlm_v2, bearer, session_cookie, token_login, oauth2_client_creds, oauth1a, saml_assertion, oidc_token, mtls, totp_mfa, webauthn_probe, apikey_header, apikey_cookie, header_creds, kerberos, kerberos_delegation, proxy_header, auto
- **JS bundle mining** (v2.16.0): scans up to 10 JS bundles (3MB each) for login URLs, API base URLs, and global config objects; detects SPA frameworks (React, Vue, Next.js, Nuxt, Gatsby, Angular, Blazor); filters SPA catch-all false positives
- **API-specific auth detection** (v2.16.0): HMAC signature, AWS SigV4, JWT bearer, unified API key (header + query), OAuth2 password grant (ROPC), cookie login
- **11 well-known endpoint probes**: OIDC, OAuth server, OpenAPI, Swagger, GraphQL, GraphQL Playground, API Docs, WSDL, SOAP, auth-info
- **MFA detection and TOTP completion**: detects MFA challenges and auto-completes TOTP when a secret is provided
- **Rendered-page fingerprinting**: optional Selenium-based headless Chrome for JS-rendered SPAs (`--rendered`)
- **Confidence scoring**: 0–95% per detected auth method with signal traceability
- **Credential validation**: per-method session building + verification against baseline
- **Universal output** (schema 1.0): `meta.json` + `findings.json` + `summary.json` when `--output-dir` is set

## Requirements

- Python 3.8+
- `requests` >= 2.28.0
- `requests-ntlm` >= 1.2.0
- `requests-kerberos` >= 0.14.0
- `pyotp` >= 2.8.0
- Chrome + ChromeDriver (optional, for `--rendered` mode)

## Installation

```bash
cd /opt/pr0t31n/AuthProbe
python3 install.py
```

## Usage

### Basic probe (detection only)

```bash
python3 authprobe.py --url https://target.example.com
```

### Probe with type hint

```bash
python3 authprobe.py --url https://api.target.com/v1 --type api
python3 authprobe.py --url https://app.target.com --type webapp
```

### Credential validation

```bash
python3 authprobe.py --url https://target.com --username admin --password secret
```

### With MFA (TOTP auto-complete)

```bash
python3 authprobe.py --url https://target.com --username admin --password secret --totp-secret BASE32SECRET
```

### Bearer token validation

```bash
python3 authprobe.py --url https://api.target.com --token eyJ...
```

### API key validation

```bash
python3 authprobe.py --url https://api.target.com --api-key abc123 --api-key-header X-API-Key
```

### Rendered-page fingerprinting (SPA targets)

```bash
python3 authprobe.py --url https://spa.target.com --rendered
```

### JSON output

```bash
python3 authprobe.py --url https://target.com --json
```

### Universal output directory (for Prometheus / pr0t31n consumers)

```bash
python3 authprobe.py --url https://target.com --output-dir /path/to/output \
    --client-short acme --client-name "Acme Corp" --engagement-name "Q4 Pentest"
```

### Session building (standalone auth validation)

```bash
python3 authprobe.py --url https://target.com --build-session --auth-method basic \
    --username admin --password secret
```

### Through a proxy

```bash
python3 authprobe.py --url https://target.com --proxy http://127.0.0.1:8080
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `--url URL` | Target URL (required) |
| `--type TYPE` | Target type: `auto` (default), `webapp`, `api` |
| `--username USER` | Username for credential validation |
| `--password PASS` | Password for credential validation |
| `--token TOKEN` | Bearer token for validation |
| `--api-key KEY` | API key value |
| `--api-key-header HDR` | Header name for API key (default: `X-API-Key`) |
| `--api-key-cookie NAME` | Cookie name for API key (default: `api_key`) |
| `--login-url URL` | Explicit login endpoint URL |
| `--totp-secret SECRET` | Base32 TOTP secret for MFA auto-complete |
| `--proxy PROXY` | HTTP proxy URL |
| `--timeout SEC` | Request timeout in seconds (default: 10) |
| `--json` | JSON output |
| `--no-verify` | Disable SSL verification |
| `--rendered` | Rendered-page fingerprinting via headless Chrome |
| `--driver-path PATH` | Path to ChromeDriver binary |
| `--output-dir DIR` | Write universal output (meta.json, findings.json, summary.json) |
| `--client-short SLUG` | Client short name for meta.json |
| `--client-name NAME` | Client full name for meta.json |
| `--engagement-name NAME` | Engagement name for meta.json |
| `--build-session` | Build and test an authenticated session |
| `--auth-method METHOD` | Force a specific auth method (with `--build-session`) |
| `--login-mode MODE` | Login POST mode: `fields`, `json`, `merge` |
| `--login-username-field` | Form field name for username (default: `username`) |
| `--login-password-field` | Form field name for password (default: `password`) |
| `--login-token-path` | Dot-path to extract token from JSON response |
| `--login-content-type` | Content-Type for login POST |
| `--session-cookie` | Pre-captured session cookie string |
| `--domain` | AD domain for NTLM/Kerberos auth |
| `--list-methods` | List all supported auth methods and exit |

## Output Files

When `--output-dir` is specified, AuthProbe writes universal schema 1.0 output:

| File | Description |
|------|-------------|
| `meta.json` | Tool identity, client, engagement metadata |
| `findings.json` | Universal findings array with detected auth methods as findings |
| `summary.json` | Aggregated statistics |

JSON output (`--json`) returns a structured result to stdout:

```json
{
    "url": "https://target.com",
    "url_type": "webapp",
    "url_type_confidence": 85,
    "auth_methods": [
        {"method": "form_login", "confidence": 65, "notes": "HTML login form detected", "signals": ["..."]}
    ],
    "software": [
        {"name": "WordPress", "confidence": 80, "indicators": ["..."]}
    ],
    "recommendations": ["form_login", "basic"],
    "findings": { ... }
}
```

## Library API

```python
from authprobe import AuthProbe

probe = AuthProbe(timeout=10, proxy="http://127.0.0.1:8080")
result = probe.probe("https://target.example.com")

for method in result["auth_methods"]:
    print(f"{method['method']}: {method['confidence']}% — {method['notes']}")
```

## Integration Points

| Tool | Integration |
|------|-------------|
| **Crucible** | Standalone tool on homepage; launched via `/api/authprobe` route; results displayed in modal |
| **Fracture** | `testConnection.py` calls `run_probe()` via `--probe` flag for detection before web app scanning |
| **Siphon** | `testConnection.py` calls `run_probe()` via `--probe` flag for detection before API scanning |
| **Prometheus** | Parses `findings.json` via universal parser when `--output-dir` is used |

AuthProbe's `build_auth_session()` function can also be imported directly for programmatic session building, though Fracture and Siphon each maintain their own testConnection.py session builders optimized for their respective domains.

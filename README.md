<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

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

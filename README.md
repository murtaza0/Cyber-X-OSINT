# Cyber X — Stateless OSINT Workspace

**Version:** 2.0.0  
**Project type:** Final Year Project · Cybersecurity / Digital Forensics / OSINT  
**Stack:** Python 3.12 · FastAPI · HTML · CSS · Vanilla JavaScript

Cyber X is a stateless OSINT workspace. It fetches permitted public-source information for one target, normalizes and correlates observations in request memory, and returns results to the browser. It does not create user accounts, investigations, scan history, evidence records, datasets or a database.

> **Authorized-use scope:** Query only publicly accessible sources and targets you are authorized to research. The collectors do not bypass logins, CAPTCHAs, paywalls, robots restrictions or access controls. The application does not access stolen credential dumps, private databases or password collections.

## 1. What it does

- Detects email, username, phone, domain, URL, IP, CIDR, file-hash and name targets.
- Selects recommended public-source modules or lets the analyst choose up to eight modules.
- Collects public HTML references from supported sites and performs passive DNS lookups.
- Displays module status, findings, source links, confidence and collection timestamps.
- Exports the current result in JSON or HTML directly in the browser.
- Uses bounded concurrency, per-module timeouts, response-size limits and public-host validation in the existing collectors.
- Protects remote deployments with an operator-configured access token.

### Collection modules

Username, email, phone, domain, IP, social, website, GitHub, network, threat references, public incident references, search, passive attack-surface context, digital-footprint context and result correlation.

Some modules return search references or contextual observations rather than authoritative verification. A public incident reference does not prove that an account or password was compromised. A missing result does not prove that information does not exist.

## 2. Stateless architecture

```text
Browser (HTML / CSS / JavaScript)
             |
             v
       FastAPI /scan
             |
             v
  Target validation and module selection
             |
             v
 Public HTML collectors + passive DNS
             |
             v
 In-memory normalization and correlation
             |
             v
 Browser response + local JSON/HTML export
```

**No database is required.** The scan response is created in memory and returned to the browser. The server does not persist target inputs or findings. JSON/HTML reports are generated locally by the browser; they are not uploaded to the server.

Vercel's temporary function filesystem is not used for scan storage. The app does not initialize SQLAlchemy, create tables, seed a source database or require PostgreSQL.

## 3. Local setup — Windows 11

Requires Python 3.11+ (Python 3.12 recommended).

```powershell
Copy-Item .env.example .env
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Local loopback development can run without an API token. If you set `APP_ENV=production`, configure `API_TOKEN`.

API schema: `/docs`  
Health check: `/health`

## 4. Vercel deployment

1. Import `murtaza0/Cyber-X-OSINT` into Vercel.
2. Set the project root to the repository root.
3. Add the environment variable `API_TOKEN` with a long random value.
4. Set `APP_ENV=production`.
5. Deploy and wait for the deployment to become **Ready**.
6. Confirm the assigned `*.vercel.app` domain is listed under Project → Settings → Domains.
7. Open the deployment and enter the same `API_TOKEN` in the access prompt.

Generate a token locally with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

No `DATABASE_URL`, PostgreSQL instance, credential encryption key or exposure HMAC key is required.

### Environment variables

| Variable | Required | Purpose |
|---|---:|---|
| `API_TOKEN` | Remote deployment | Protects scan and module endpoints |
| `APP_ENV` | Recommended | Use `production` on Vercel; `development` locally |
| `REQUEST_TIMEOUT_SECONDS` | No | Per-module timeout baseline (bounded by the API) |
| `USER_AGENT` | No | Identifies the public-web collector |
| `LOG_LEVEL` | No | Application log verbosity |

## 5. API

### `POST /api/v1/scan`

Request:

```json
{
  "target": "example.com",
  "modules": ["domain", "website", "search"]
}
```

Omit `modules` to use the recommended modules for the detected target type. A maximum of eight supported modules can be selected.

The response contains the normalized target, collection timestamp, per-module status, findings, source URLs, confidence values, limitations and a `storage: "memory_only"` marker.

### `GET /api/v1/modules`

Returns the supported module catalog.

Both endpoints require `X-API-Token` when `API_TOKEN` is configured.

## 6. Security and operational limits

- No password, token, cookie or private credential collection.
- No private-database connector, credential reveal, or breach-dump search.
- No login-gated scraping, CAPTCHA evasion or access-control bypass.
- No port scanning or host discovery for CIDR ranges.
- Website collectors reject non-public destinations and disallow non-standard ports.
- Public-source failures and rate limits are surfaced as module status, not hidden.
- Collection is bounded to one target and at most eight modules per request.

For a public production deployment, protect the token, monitor usage and consider an edge/WAF rate limit. The token is an access gate, not multi-user identity management or role-based access control.

## 7. Testing

Run the available tests:

```powershell
python -m pytest -q
```

Before release, verify locally:
- `GET /health` returns `status=ok`.
- `GET /api/v1/modules` returns the module catalog.
- `POST /api/v1/scan` returns `storage=memory_only`.
- No database URL is required and no database file is created.
- JSON and HTML exports are generated by the browser.

## 8. Project documentation

- [Architecture](docs/ARCHITECTURE.md)
- [FYP project report](docs/FYP-PROJECT-REPORT.md)
- [Security review](docs/SECURITY-REVIEW.md)
- [Testing](docs/TESTING.md)
- [Module status](docs/MODULE-STATUS.md)
- [Build status](BUILD-STATUS.md)
- [Changelog](CHANGELOG.md)

---

**Cyber-X-OSINT v2.0.0** — Stateless public-source intelligence for cybersecurity research.

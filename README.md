# CYBER X — OSINT & Data Exposure Intelligence Platform

**Version:** 1.5.0  
**Project type:** Final Year Project (FYP) · Cybersecurity / Digital Forensics / OSINT  
**Stack:** Python 3.12 · FastAPI · SQLAlchemy · HTML · CSS · Vanilla JavaScript · SQLite/PostgreSQL

Cyber X is a self-hosted intelligence workspace for investigations, public-web collection, passive attack-surface review, redacted exposure-index correlation, evidence integrity, entity correlation, audit trails and report generation.

> **Scope notice:** Use only public pages that permit automated access, synthetic datasets, records you own, or information you are explicitly authorized to assess. The collectors do not bypass logins, CAPTCHAs, paywalls, robots restrictions or access controls. The Exposure Dataset Lab accepts redacted identifier indexes only; raw stolen credential dumps, passwords, tokens, cookies and credential pairs are rejected.

## 1. Features

### Investigation workspace
- Investigation/case creation, target identification and bulk target import.
- Automatic target classification: email, username, domain, URL, IP, CIDR, phone and file hash.
- Collection jobs with module status, visible failures and per-finding confidence.
- Evidence vault with SHA-256 integrity digests, timeline, entity graph and source provenance.
- Export to JSON, HTML and PDF.

### Public-source intelligence
- Public HTML search-result scraping from DuckDuckGo HTML.
- Certificate Transparency page parsing from crt.sh HTML.
- GitHub public profile and repository-page parsing from ordinary HTML.
- URLhaus public browse-page parsing.
- Hurricane Electric public routing-page parsing.
- Website title, metadata, headers, technology hints and public links.
- DNS record collection through DNS protocol lookups.
- Username, email, social and breach-disclosure search references.
- Request timeouts, response-size limits, URL safety validation and access-denial handling.

No third-party intelligence API keys are required by the collection workflow. The `/api/v1/` routes are the application's own backend interface, not external provider APIs.

### Exposure Dataset Lab
- Import redacted CSV indexes supplied by the analyst or created from synthetic classroom data.
- Accepts `email`, `username`, `domain`, `breach_name`, `breach_date`, and `source_reference`.
- Rejects columns suggesting passwords, password hashes, credentials, secrets, tokens, cookies, sessions or raw dumps.
- Normalizes identifiers and stores keyed HMAC-SHA256 digests.
- Matches investigation targets against imported indexes.
- Records audit events for imports, deletions and checks.
- Includes synthetic sample data at `sample_data/synthetic_exposure_index.csv`.

A match means the identifier exists in an analyst-imported index. It is not proof that a password was leaked or that an account is currently compromised.

### Additional capabilities
- Optional encrypted storage of analyst-entered credentials for authorized lab assessments.
- Offline weak-password heuristics.
- Optional owner-configured PostgreSQL connector with read-only parameterized queries.
- Evidence metadata, file fingerprinting and supported local document/image metadata extraction.
- Entity extraction, correlation relationships, investigation timeline and audit log.
- Protected workspace access token and security headers.
- Docker configuration and Windows/Linux run scripts.

## 2. Architecture

```text
Browser UI (static HTML/CSS/JS)
          |
          v
FastAPI application (app/main.py)
          |
          +-- Investigation & target services
          +-- Public HTML collectors / DNS lookups
          +-- Exposure Dataset Lab
          +-- Evidence, correlation and reporting
          |
          v
SQLAlchemy data layer
     +-- SQLite (local development)
     +-- PostgreSQL (persistent hosted deployment)
```

## 3. Local setup — Windows 11

Requires Python 3.12.

Open PowerShell in the project root:

```powershell
Copy-Item .env.example .env
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Generate secrets:

```powershell
python -c "import secrets; print('API_TOKEN=' + secrets.token_urlsafe(48)); print('EXPOSURE_HMAC_KEY=' + secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print('CREDENTIAL_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
```

Put the generated values in `.env`.

Start the application:

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`.

API documentation is available at `/docs`.

## 4. GitHub

Do not upload `.env`, `.venv`, storage directories, database files, real incident datasets or secrets.

The `.gitignore` excludes local environment files, virtual environments, storage, generated artifacts and secrets.

## 5. Vercel deployment

1. Import the GitHub repository into Vercel.
2. Set the project root to the repository root.
3. Configure the required environment variables.
4. Configure a persistent PostgreSQL database.
5. Deploy and verify `/health`.

### Required environment variables

| Variable | Purpose |
|---|---|
| `APP_ENV` | Set to `production` |
| `API_TOKEN` | Strong application access token |
| `DATABASE_URL` | Persistent PostgreSQL connection URI |
| `EXPOSURE_HMAC_KEY` | Stable secret for keyed identifier matching |
| `CREDENTIAL_ENCRYPTION_KEY` | Fernet encryption key |
| `USER_AGENT` | Collector identification string |
| `MAX_UPLOAD_MB` | Upload limit; optional |
| `REQUEST_TIMEOUT_SECONDS` | Request timeout; optional |

**Important:** Vercel function storage is not durable. Use persistent PostgreSQL for hosted investigations, findings, audit records and exposure indexes. Uploaded binary evidence is temporary unless persistent object storage is added.

See the [FastAPI on Vercel guide](https://vercel.com/docs/frameworks/backend/fastapi) and [Python runtime documentation](https://vercel.com/docs/functions/runtimes/python).

## 6. Redacted CSV schema

```csv
email,username,domain,breach_name,breach_date,source_reference
alice@example.test,alice,example.test,Synthetic University Exercise,2026-01-15,https://example.test/report
```

At least one of `email`, `username` or `domain` must be populated. Never include passwords, password hashes, API keys, cookies, tokens, session material or raw credential dumps.

## 7. Testing

Run:

```powershell
python -m pytest -q
```

See `docs/TESTING.md` for the test plan.

## 8. Known limitations

- Public HTML structures and search-engine response policies can change.
- Search results are investigative leads, not authoritative confirmation.
- No login-gated scraping, private-database intrusion, credential-dump harvesting or access-control evasion is provided.
- Dataset matching is limited to analyst-imported redacted indexes.
- Large-scale collection requires a durable queue/worker architecture.
- Vercel binary evidence uploads require persistent object storage for durability.
- The project provides access-token protection, not a full multi-user identity/RBAC platform.

## 9. Project documentation

- [Architecture](docs/ARCHITECTURE.md)
- [FYP project report](docs/FYP-PROJECT-REPORT.md)
- [Security review](docs/SECURITY-REVIEW.md)
- [Testing](docs/TESTING.md)
- [Module status](docs/MODULE-STATUS.md)
- [Build status](BUILD-STATUS.md)
- [Changelog](CHANGELOG.md)

---

**Cyber-X-OSINT v1.5.0** — Final Year Project in Cybersecurity, Digital Forensics and OSINT.
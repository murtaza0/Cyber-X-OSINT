# CYBER X — OSINT & Data Exposure Intelligence Platform

**Version:** 1.5.0  
**Project type:** Final Year Project (FYP) · Cybersecurity / Digital Forensics / OSINT  
**Stack:** Python 3.12 · FastAPI · SQLAlchemy · HTML · CSS · Vanilla JavaScript · SQLite/PostgreSQL

Cyber X is a self-hosted intelligence workspace for investigations, public-web collection, passive attack-surface review, redacted exposure-index correlation, evidence integrity, entity correlation, audit trails and report generation.

> **Scope notice:** Use only public pages that permit automated access, synthetic datasets, records you own, or information you are explicitly authorized to assess. The collectors do not bypass logins, CAPTCHAs, paywalls, robots restrictions or access controls. The Exposure Dataset Lab accepts redacted identifier indexes only; raw stolen credential dumps, passwords, tokens, cookies and credential pairs are rejected.

## 1. What is implemented

### Investigation workspace
- Investigation/case creation, target identification and bulk target import.
- Automatic target classification: email, username, domain, URL, IP, CIDR, phone and file hash.
- Collection jobs with module status, visible failures and per-finding confidence.
- Evidence vault with SHA-256 integrity digests, timeline, entity graph and source provenance.
- Export to JSON, HTML and PDF.

### Public-source intelligence — no third-party API keys
- Public HTML search-result scraping from DuckDuckGo HTML.
- Certificate Transparency page parsing from crt.sh HTML.
- GitHub public profile and repository-page parsing from ordinary HTML.
- URLhaus public browse-page parsing.
- Hurricane Electric public routing-page parsing.
- Website title, metadata, headers, technology hints and public links.
- DNS record collection through DNS protocol lookups (not an HTTP provider API).
- Username, email, social and breach-disclosure search references.
- Robots.txt checks, bounded response size, request timeout, same-host redirect checks, public-IP validation and skip-on-401/403/429 behavior.

The app does not call GitHub REST/GraphQL APIs, HIBP, Pwned Passwords, commercial breach APIs or third-party intelligence APIs. The ` /api/v1/ ` routes are the application's own private backend interface for its frontend; they are not external provider APIs.

### Exposure Dataset Lab
- Import a **redacted CSV index** supplied by the analyst or created from synthetic classroom data.
- Accepts only: `email`, `username`, `domain`, `breach_name`, `breach_date`, `source_reference`.
- Rejects columns suggesting passwords, password hashes, credentials, secrets, tokens, cookies, sessions or raw dumps.
- Normalizes identifiers and stores keyed HMAC-SHA256 digests. The original email/username/domain values from the CSV are not persisted.
- Matches an investigation target against imported indexes and returns masked identifiers, incident labels, dates and provenance references.
- Audit events record imports, deletions and checks. Raw CSV upload bytes are parsed in memory and discarded.
- Includes synthetic sample data at `sample_data/synthetic_exposure_index.csv`.

A match means the identifier exists in an analyst-imported index. It is not proof that a particular password was leaked or that an account is currently compromised. Provenance must be checked independently. Public incident searches include the email target in a query sent to the search-engine website; use that function only for identifiers you are authorized to disclose to that public source.

### Credential and database hygiene
- Optional encrypted storage of analyst-entered credentials for owner-authorized lab assessments; hidden by default, audited reveal and secret-free reports.
- Offline weak-password heuristics. A candidate is evaluated in-process and is not persisted or sent to an external service. This is not a leaked-password corpus lookup.
- Optional owner-configured PostgreSQL connector using direct SQL protocol and read-only parameterized count queries against a server-side allowlist. This is not an external HTTP API. Use a database account with least privilege and explicit written authorization.

### Reporting and operations
- Evidence metadata, file fingerprinting and supported local document/image metadata extraction.
- Entity extraction, correlation relationships, investigation timeline and audit log.
- Protected workspace access token, security headers and URL safety validation.
- Docker configuration and Windows/Linux run scripts.

## 2. Architecture

```text
Browser UI (static HTML/CSS/JS)
          |
          | same-origin HTTPS requests
          v
FastAPI application (app/main.py)
          |
          +-- Investigation & target services
          +-- Public HTML collectors / DNS lookups
          +-- Exposure Dataset Lab (CSV -> validation -> keyed HMAC)
          +-- Evidence, correlation, audit and PDF/HTML reporting
          |
          v
SQLAlchemy data layer
    +-- SQLite (local development)
    +-- PostgreSQL (persistent hosted deployment)
```

There are no third-party API keys or external service API dependencies in the collection workflow. The frontend uses the application's own HTTP routes to communicate with FastAPI.

## 3. Run locally on Windows 11

Install Python 3.12, then open PowerShell in the project root:

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

Put the generated values in `.env`. Then start the application:

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. The first screen asks for the `API_TOKEN` value; this is the access token for your own Cyber X deployment, not a third-party API key. API documentation is at `/docs`.

For a quick test of the Exposure Dataset Lab, import `sample_data/synthetic_exposure_index.csv`, create an investigation, add `alice@example.test` as an email target, then run **Exposure Dataset Lab → Match an investigation target**.

## 4. GitHub upload

Create a new empty repository on GitHub. Do not upload `.env`, `.venv`, `storage/`, database files, real incident datasets or secrets.

```powershell
git init
git add .
git commit -m "Release Cyber X OSINT 1.5.0"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
git push -u origin main
```

The `.gitignore` excludes the local environment, virtual environment, storage, generated artifacts and secrets.

## 5. Deploy from GitHub to Vercel

Vercel's Python runtime supports FastAPI applications, and Python 3.12 is supported. Vercel recognizes `app/main.py` as a FastAPI entrypoint; this repository sets its function duration in `vercel.json` and pins Python with `.python-version`. See the official [FastAPI on Vercel guide](https://vercel.com/docs/frameworks/backend/fastapi) and [Python runtime documentation](https://vercel.com/docs/functions/runtimes/python).

1. Sign in to Vercel and choose **Add New → Project**.
2. Import the GitHub repository.
3. Set the project root to the repository root (the folder containing `vercel.json` and `requirements.txt`).
4. Choose the Python/Other detected configuration. Do not add a frontend build command; the UI is already plain static HTML/CSS/JavaScript.
5. Add the environment variables below before the first production deployment.
6. Deploy, then open the deployment URL. The protected-access screen should appear.

### Required Vercel environment variables

| Variable | Value |
|---|---|
| `APP_ENV` | `production` |
| `API_TOKEN` | A long random token generated by you; never commit it |
| `DATABASE_URL` | A persistent PostgreSQL connection URI from a database you control |
| `EXPOSURE_HMAC_KEY` | Random secret, at least 32 characters; keep stable across deployments |
| `CREDENTIAL_ENCRYPTION_KEY` | Fernet key generated by the command above; keep stable or stored credentials cannot be decrypted |
| `USER_AGENT` | `Cyber-X-OSINT/1.5 (+contact: your-email-or-project-site)` |
| `MAX_UPLOAD_MB` | `15` (optional) |
| `REQUEST_TIMEOUT_SECONDS` | `8` (optional) |

**Important about storage:** Vercel Functions use a read-only filesystem with writable temporary `/tmp` storage. That temporary storage is not durable between invocations. Configure `DATABASE_URL` to a persistent PostgreSQL database for investigations, findings, audit records and exposure indexes. Do not rely on the default SQLite `/tmp` file for production data. Uploaded evidence files are processed in temporary storage; the database retains their digest and metadata, not a durable copy of the uploaded binary. See [Vercel runtime filesystem support](https://vercel.com/docs/functions/runtimes#file-system-support).

The database is accessed with the PostgreSQL wire protocol/driver, not a third-party HTTP API. You need a PostgreSQL server for hosted persistence. The application refuses to start on Vercel with SQLite so it cannot appear to work while silently losing case data when a function instance is recycled.

### After deployment

- Visit `/health` and confirm the response reports version `1.5.0`.
- Open the project URL and enter the `API_TOKEN` value.
- Create a test investigation and import only the synthetic CSV first.
- Check the Vercel function logs if the backend returns an error.
- Verify that `DATABASE_URL` points to PostgreSQL before loading real assessment metadata.

## 6. Configuration reference

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLAlchemy database URL; local SQLite by default, PostgreSQL for persistent deployment |
| `API_TOKEN` | Access token protecting this application's backend routes |
| `CREDENTIAL_ENCRYPTION_KEY` | Fernet key for optional authorized credential records |
| `EXPOSURE_HMAC_KEY` | Stable secret used to keyed-HMAC identifier values in imported exposure indexes |
| `AUTHORIZED_DATABASES_JSON` | Optional owner-approved PostgreSQL connector allowlist |
| `MAX_UPLOAD_MB` | Evidence file upload limit; default 15 MB |
| `REQUEST_TIMEOUT_SECONDS` | Outbound public-source request timeout |
| `USER_AGENT` | Collector identification string |
| `LOG_LEVEL` | Logging level |

## 7. Redacted CSV schema

The Exposure Dataset Lab imports rows in this format:

```csv
email,username,domain,breach_name,breach_date,source_reference
alice@example.test,alice,example.test,Synthetic University Exercise,2026-01-15,https://example.test/report
```

At least one of `email`, `username` or `domain` must be populated. Do not include passwords, password hashes, API keys, cookies, tokens, session material, credential pairs or raw dump content. Values are normalized and converted to keyed HMAC digests before database insertion. A stable `EXPOSURE_HMAC_KEY` is necessary to match previously imported indexes after redeployment.

## 8. Testing

```powershell
python -m pytest -q
```

The suite covers target detection, encryption, collection jobs, report exports, upload limits, authorization gates, URL validation, private-address rejection, DNS posture parsing, IPv6 entity extraction, Exposure Lab CSV validation, HMAC privacy and target matching.

## 9. Known limitations

- Public HTML structure and search-engine response policies can change; collectors report failures rather than inventing results.
- Search results are investigative leads. They are not authoritative confirmation of an incident or compromise.
- No login-gated scraping, private-database intrusion, credential-dump harvesting, password collection, CAPTCHA bypass or access-control evasion is provided.
- Dataset matching is exact and limited to analyst-imported redacted indexes. It does not crawl hidden services or acquire stolen datasets.
- In-process collection jobs are suitable for an FYP/MVP and short workflows. Large-scale jobs should move to a durable queue/worker architecture.
- Uploaded binary evidence is temporary on Vercel unless a persistent object-storage layer is added. Metadata and digests are stored in the configured database.
- The project provides access-token protection, not a full multi-user identity/RBAC platform.

## 10. FYP deliverables

See `docs/FYP-PROJECT-REPORT.md` for the abstract, objectives, methodology, architecture, module descriptions, test plan, ethical scope and viva preparation notes.

# Cyber-X-OSINT v1.5.0

OSINT and data-exposure intelligence platform for public-source research and analyst-authorized datasets.

## Features
- Public web, DNS, username, domain, and IP intelligence collectors
- Public breach-disclosure references
- Analyst-provided, redacted exposure-index ingestion
- Keyed HMAC matching for exposure indicators
- Investigation records, evidence metadata, audit history, and reporting
- FastAPI backend with a responsive HTML/CSS/JavaScript interface
- Vercel deployment entrypoint

## Safety and data handling
This project is designed for public sources and datasets the analyst is authorized to process. It does not bypass authentication, access private databases without permission, or collect stolen passwords. Exposure imports reject secret/password fields and store keyed indicator digests rather than raw identifiers.

## Local setup
Requires Python 3.12.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
.`run.ps1
```

Open the local URL printed by the runner.

## Vercel deployment
1. Import this repository into Vercel.
2. Configure the environment variables described in `.env.example`.
3. Configure a persistent PostgreSQL database and set `DATABASE_URL`.
4. Set `APP_ENV=production`, a strong `API_TOKEN`, and a unique `EXPOSURE_HMAC_KEY`.
5. Deploy.

Vercel's function filesystem is ephemeral. Production mode requires persistent PostgreSQL; do not use local SQLite for hosted case data. Binary evidence uploads are temporary in the serverless deployment, while evidence metadata and hashes persist.

## Project documentation
- [Architecture](docs/ARCHITECTURE.md)
- [FYP project report](docs/FYP-PROJECT-REPORT.md)
- [Security review](docs/SECURITY-REVIEW.md)
- [Testing](docs/TESTING.md)
- [Module status](docs/MODULE-STATUS.md)
- [Build status](BUILD-STATUS.md)
- [Changelog](CHANGELOG.md)

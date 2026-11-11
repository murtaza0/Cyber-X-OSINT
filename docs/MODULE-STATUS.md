# Module Status — Cyber X 1.5.0

| Module | Capability | Status |
|---|---|---|
| Investigation management | Cases, targets, jobs and dashboard | Implemented |
| Domain | DNS records, SPF/DMARC presence and certificate-transparency HTML | Implemented |
| IP | Classification, reverse DNS and public routing-page HTML | Implemented |
| Website | Public metadata, headers, technology hints and links | Implemented |
| Username | Public profile pages and references | Implemented |
| Email | Normalization, DNS posture and public references | Implemented |
| Phone | Normalization and calling-prefix estimate | Baseline |
| GitHub | Public profile and repository HTML parsing; no GitHub API | Implemented |
| Search / Social | Public HTML search references | Implemented |
| Breach | Public incident-disclosure references and analyst verification | Implemented |
| Exposure Dataset Lab | Redacted CSV ingestion, HMAC indexing and exact target matching | Implemented |
| Credential | Encrypted analyst-entered records and offline weak-password heuristics | Implemented |
| Authorized database | Owner-configured read-only PostgreSQL count lookup | Optional integration |
| Threat | Public URLhaus browse-page parsing | Implemented |
| Evidence | SHA-256 integrity metadata, uploads and metadata extraction | Implemented (binary retention is ephemeral on Vercel) |
| Correlation | Entity extraction, relationships and timeline | Implemented |
| Reports | JSON, HTML and PDF | Implemented |
| Source manager | Source registry and provenance references | Implemented |
| Audit | Security and analyst action events | Implemented |

## Collection model

- HTTP intelligence sources are parsed from public HTML, not provider JSON/REST APIs.
- DNS data is collected through DNS protocol lookups.
- External source content is not treated as instructions and is not executed.
- No authentication bypass, private account scraping, CAPTCHA bypass or raw stolen credential import is implemented.

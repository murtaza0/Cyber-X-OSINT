# Cyber X OSINT — Build 1.5.0 Delivery Status

## Implemented

- Premium dark command-center UI with responsive navigation and dedicated Exposure Dataset Lab.
- Investigation/case management, target classification, bulk target import and collection job tracking.
- Public HTML collection for search results, GitHub profile pages, crt.sh certificate pages, URLhaus browse pages and public routing reference pages.
- DNS-based domain intelligence, SPF/DMARC presence checks and passive IP/network classification.
- Website metadata, HTTP headers, technology hints and public links.
- Robots.txt awareness, public-IP destination checks, bounded downloads, timeout and redirect controls.
- Redacted exposure CSV ingestion with strict schema allowlist, raw-secret field rejection, keyed HMAC-SHA256 identifier storage and exact target matching.
- Encrypted authorized analyst-entered credential records, local weak-password heuristics and owner-authorized read-only PostgreSQL lookup.
- Evidence digests, timeline, entity correlation graph, audit events and JSON/HTML/PDF reporting.
- Vercel-native FastAPI entrypoint (`app/main.py`), fail-fast persistent-PostgreSQL requirement, GitHub deployment documentation and production storage guidance.
- Synthetic sample exposure index and FYP project report draft.

## Validation performed in this build

- Python compilation: passed.
- JavaScript syntax validation (`node --check static/app.js`): passed.
- Automated regression tests: **24 passed**.
- Exposure Dataset Lab tests cover CSV import, three identifier types, HMAC storage, exact matching, raw-password header rejection and missing HMAC-key configuration.
- Tests cover target classification, collection jobs, credential encryption/reveal auditing, report exports, upload limits, workspace token enforcement, safe URL handling, private-IP rejection, IPv6 parsing and security headers.

## Deployment notes

- Local development uses SQLite.
- Vercel uses the native FastAPI entrypoint at `app/main.py`; the application fails startup unless `DATABASE_URL` points to persistent PostgreSQL.
- Uploaded evidence binaries are processed in temporary storage; evidence metadata and digests persist in the configured database. Durable binary storage would require a separate object-storage implementation.
- In-process collection tasks are suitable for an FYP demonstration and small workflows, not large-scale continuous crawls.

## Explicit scope boundaries

- Third-party intelligence-provider APIs are not used.
- Public HTML and DNS collectors operate only within public/allowed scope.
- No unauthorized private database access, authentication bypass, password dump acquisition, stolen credential collection, CAPTCHA evasion or access-control circumvention is included.
- Exposure matching only analyzes redacted analyst-supplied or synthetic identifier indexes.

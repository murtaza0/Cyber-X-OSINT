# Changelog

## 1.5.0 — FYP Exposure Intelligence Release

- Added Exposure Dataset Lab with strict redacted-CSV import.
- Added keyed HMAC-SHA256 indexing of email, username and domain identifiers; raw identifiers from uploaded indexes are not persisted.
- Added exact-match exposure checks within an investigation, masked result display, provenance metadata and audit events.
- Added rejection of password, password-hash, credential, secret, token, cookie, session and dump columns.
- Added synthetic sample data and CSV template.
- Removed obsolete provider API setup documentation and aligned the credential module to local-only weak-password checks.
- Added Vercel/GitHub setup instructions, persistent PostgreSQL requirements, FYP report draft and refreshed module/security docs.
- Added tests for import, matching, HMAC privacy, secret-column rejection and key configuration.

## 1.4.0 — HTML-first / Vercel release

- Removed third-party JSON/API provider dependencies and moved supported source collection to public HTML parsing.
- Added Vercel Python Function entrypoint and production access-token gate.
- Added local-only weak-password heuristics and Vercel persistence guidance.

## 1.2.0

- Original public-source OSINT workspace, evidence, reports, correlation and encrypted analyst-entered credential records.

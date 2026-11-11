# Testing Plan — Cyber X 1.5.0

Run automated checks from the repository root:

```powershell
python -m pytest -q
node --check static/app.js
python -m compileall -q app
```

The automated suite covers:

- Target classification, malformed URL rejection and IPv6 handling.
- Investigation and target creation, collection jobs and per-module error handling.
- Credential encryption, audited reveal, and secret-free JSON/HTML/PDF reports.
- Upload size/type validation and SHA-256 evidence metadata.
- Local-only password hygiene; verifies there is no external password-provider request.
- Public incident reference search and result provenance fields.
- Owner-configured database schema allowlisting and count-only result handling.
- Remote workspace access-token gate, security headers and Vercel SQLite fail-fast guard.
- Robots-aware public HTTP and rejection of private/non-global collection destinations.
- Redacted exposure CSV ingestion, HMAC matching, secret-column rejection and HMAC-key configuration.

## Manual demonstration scenarios

1. Start the app and unlock it using the local `API_TOKEN` if configured.
2. Create an investigation named `FYP Demonstration — Synthetic Dataset`.
3. Add `alice@example.test` as an email target.
4. Open Exposure Dataset Lab and import `sample_data/synthetic_exposure_index.csv`.
5. Select the investigation and target, provide a class-project authorization context, and run the index match.
6. Confirm a synthetic match appears with masked identifier and source provenance.
7. Delete the sample dataset and confirm it disappears from the index list.
8. Run a public domain collection against a domain you control; review findings and source errors.
9. Export JSON, HTML and PDF reports and inspect the evidence digest and audit trail.

## Performance evaluation

For the report, record the machine/runtime, sample size, source mix, request duration, successful fetches, parser failures, deduplication counts and matching results. Use synthetic ground-truth data. Do not claim accuracy percentages without a labelled test dataset and reproducible methodology.

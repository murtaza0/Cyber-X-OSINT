# Security Review — Cyber X 1.5.0

## Controls

- Public-source HTTP targets are normalized; userinfo and non-standard ports are rejected.
- DNS resolution must return globally routable IP addresses. Redirects are revalidated and constrained by source host where required.
- Public page collection checks robots.txt and refuses 401/403 responses.
- HTTP collection has request timeouts, response-size bounds and redirect limits.
- The app sends a configurable User-Agent and does not attempt login, CAPTCHA or access-control bypass.
- The Exposure Dataset Lab enforces an allowlist CSV schema and rejects password, secret, token, cookie, session, credential and dump columns.
- Identifier values are normalized and converted to HMAC-SHA256 before persistence; a deployment secret is required.
- Workspace routes require API_TOKEN for remote/production requests.
- Credential records are encrypted at rest and reveal actions are audited.
- Reports do not include decrypted credentials.
- File uploads are bounded by MAX_UPLOAD_MB and allowed suffixes.

## Operational requirements

- Keep `.env`, database URIs, access tokens, HMAC keys and encryption keys out of Git.
- Use HTTPS and a persistent PostgreSQL database for hosted production data.
- Keep `EXPOSURE_HMAC_KEY` stable; rotating it requires re-indexing imported identifier datasets.
- Back up PostgreSQL and encryption secrets separately.
- Restrict database connector egress and grant SELECT-only permissions on explicit tables.
- Treat public search references as leads that need independent analyst verification.

## Known limitations

- Vercel function filesystem data under `/tmp` is temporary. Uploaded binary evidence is not durable without object storage.
- The in-process collection runner is not a durable distributed queue.
- The access-token gate is a single-operator MVP control, not a full identity and role system.
- Public HTML layout changes can break a parser.

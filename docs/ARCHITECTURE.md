# Architecture Notes

## High-level flow

1. The analyst creates an investigation and submits one or more targets.
2. `app.core.targets` normalizes the target and selects recommended modules.
3. The API persists a `CollectionJob` and schedules `run_collection_job` as a FastAPI background task.
4. Module adapters in `app.collectors.collectors` retrieve configured public observations.
5. `app.services.collection` stores findings and evidence digests.
6. `app.services.correlation` extracts bounded email/domain/IP references and creates graph nodes/edges linked to the investigation.
7. The API exposes jobs, findings, evidence, timeline, graph and report views.

## Exposure Dataset Lab

- An `ExposureDataset` row stores dataset name, provenance label, row count and a SHA-256 fingerprint of the original upload.
- `ExposureIndicator` rows store an indicator type, keyed HMAC-SHA256 digest, masked display value and non-secret incident metadata.
- Original uploaded CSV bytes and full source identifiers are not persisted by the import routine.
- Imported rows are checked against investigation targets by the same stable HMAC key; matches create findings, evidence digests and audit events.
- The importer rejects credential, password, token, cookie, session, hash and raw-dump columns.

## Data ownership

- Investigation and target rows own case context.
- A collection job records the modules and execution state.
- A finding represents one observation and retains module, confidence, source URL and verification status.
- An evidence row stores a SHA-256 digest over the captured observation metadata and a bounded excerpt.
- Entity and relationship rows form an investigation-scoped graph.
- Credential records store a Fernet-encrypted password field; plaintext is returned only by the explicit reveal endpoint and is not included in list/report APIs.
- Audit rows capture administrative actions and credential reveals without recording secret values.

## Collector contract

Every collector returns a list of dictionaries with:

```python
{
    "module": "domain",
    "finding_type": "dns_records",
    "value": "...",
    "details": {},
    "source_url": "https://... or None",
    "confidence": 0.0,
    "verification_status": "observed | unverified | source_error"
}
```

A module adapter should only mark an observation as observed when it actually retrieved it from a source. A generated search link is a reference for analyst review, not a discovered fact. Public HTML adapters parse permitted pages; no third-party provider API is called.

## Security design notes

- Public HTTP collectors disable implicit environment proxies, validate scheme/port and preflight every resolved address as globally routable, and follow a bounded number of redirects.
- When `API_TOKEN` is unset, API requests are accepted only from loopback clients. Docker and remote deployments require an explicit token.
- Browser responses include a restrictive Content Security Policy and anti-framing/content-sniffing headers.
- This preflight is not a substitute for a production egress firewall or a DNS-pinning transport; enforce outbound network policy at the host/container boundary before exposing the service.
- Uploads are size-limited and parsed as data only. They are not executed.
- No authentication-gated scraping, SMTP mailbox probing, CAPTCHA bypass, raw stolen-dataset ingestion or leaked-password harvesting is implemented.
- Credential values are encrypted at rest and excluded from reports, normal list endpoints and audit details.

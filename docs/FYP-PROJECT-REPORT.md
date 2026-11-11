# CYBER X — OSINT & Data Exposure Intelligence Platform

## Final Year Project Report (Implementation Draft)

**Discipline:** Cybersecurity / Digital Forensics / Information Security  
**Version:** 1.5.0  
**Implementation stack:** Python 3.12, FastAPI, SQLAlchemy, SQLite/PostgreSQL, HTML, CSS and JavaScript

> Replace the student/institution/supervisor fields and add actual screenshots, evaluation measurements and references required by the department before final submission. Do not present synthetic test data as real breach evidence.

## Abstract

Cyber X is a web-based OSINT and data-exposure intelligence workspace designed to support structured investigations using publicly accessible web information and analyst-provided redacted exposure indexes. The system organizes investigations, normalizes targets, collects passive public-source observations, correlates entities, preserves evidence integrity metadata, and generates investigation reports. Its Exposure Dataset Lab imports a restricted CSV schema and converts identifiers to keyed HMAC-SHA256 digests before persistence. This allows authorized exact-match analysis without retaining raw identifiers from imported data or ingesting passwords and credential dumps. The platform uses a FastAPI backend, a browser-based interface, SQLAlchemy persistence and HTML parsing instead of external intelligence-provider APIs. A local SQLite database supports development, while PostgreSQL is supported for persistent cloud deployment.

## Problem Statement

Security analysts often perform investigations across separate tools and manually maintain targets, source references, evidence and incident notes. This fragments the investigation process, makes provenance difficult to track and increases the chance of retaining unnecessary sensitive material. A unified workspace is useful for organizing publicly collected observations and comparing authorized indicators against a documented, redacted exposure index.

## Aim

To design and implement a web-based OSINT platform that centralizes public-source collection, investigation management, redacted data-exposure matching, evidence integrity and reporting without depending on third-party intelligence APIs.

## Objectives

1. Build investigation and target-management workflows.
2. Implement passive collectors for public HTML pages and DNS records.
3. Enforce request safety through robots checks, public-host validation, bounded responses and redirect restrictions.
4. Import redacted identifier indexes using a strict CSV schema.
5. Protect imported identifiers with keyed HMAC-SHA256 before storage.
6. Match investigation targets against imported indexes and preserve an audit record.
7. Maintain evidence digests, timeline events and entity relationships.
8. Generate JSON, HTML and PDF reports.
9. Package the application for local operation and GitHub-to-Vercel deployment.

## Scope

### Included
- Publicly accessible HTML collection where permitted by the source.
- DNS posture collection and passive network metadata.
- Public profile/search references, certificate transparency page parsing, public threat reference pages and public website metadata.
- Analyst-supplied redacted dataset ingestion and exact identifier matching.
- Investigation, target, evidence, audit, correlation and reporting features.
- Owner-configured PostgreSQL database lookup with read-only allowlists.

### Excluded
- Authentication bypass, scraping private accounts, CAPTCHA evasion or access-control circumvention.
- Acquisition of stolen database dumps, stealer logs, credential lists or passwords.
- Storing raw passwords or credential pairs in Exposure Dataset Lab.
- Exploit attempts, active port scanning or destructive tests.
- Claims that search-engine results are authoritative breach confirmations.

## System Architecture

```text
Analyst Browser
   | same-origin HTTPS
   v
FastAPI Application
   |-- Access-token gate
   |-- Investigation and target manager
   |-- Public HTML/DNS collectors
   |-- Redacted CSV ingestion and validation
   |-- HMAC exposure-index matching
   |-- Evidence, correlation and reporting
   v
SQLAlchemy Persistence Layer
   |-- SQLite for local development
   |-- PostgreSQL for hosted persistence
```

The browser communicates with the application's own backend endpoints. The collectors do not call external provider APIs. Direct DNS lookups use the DNS protocol; public web adapters parse permitted HTML pages. Public incident search sends the selected email address as a query to the search-engine website, so the operator must have authorization to disclose that identifier to the source.

## Methodology

### 1. Target normalization

Targets are classified as email, username, domain, URL, IP, CIDR, phone, file hash or free-form name. Normalization reduces inconsistent comparisons and selects relevant collection modules.

### 2. Public-source collection

The collector retrieves bounded HTML responses, checks robots.txt where applicable, validates that resolved hosts are globally routable, limits redirects and request duration, and parses selected page metadata. Source failures are recorded as failures rather than represented as successful observations.

### 3. Exposure-index processing

An analyst supplies a CSV index with only the accepted metadata columns. The importer rejects headers that imply secret or credential material. It normalizes email, username and domain values, creates keyed HMAC-SHA256 digests and persists only those digests with masked identifiers and incident metadata. The uploaded CSV is not stored as a raw artifact.

### 4. Correlation

A selected investigation target is normalized and keyed using the same stable secret. The platform performs an exact digest lookup and returns dataset provenance, incident label/date and masked identifier. The application records a finding, evidence digest and audit event.

### 5. Evidence and reporting

Findings carry source references, confidence values and verification status. Evidence records store SHA-256 digests and excerpts. The report generator exports investigation data to JSON, HTML or PDF while excluding encrypted credential content.

## Main Modules

| Module | Purpose |
|---|---|
| Command Center | Investigation metrics and recent findings |
| Investigations | Case, target and collection-job management |
| Domain Intelligence | DNS posture and certificate-transparency HTML references |
| IP / Network Intelligence | IP classification, reverse DNS and passive routing references |
| Website Intelligence | Public page metadata, headers, technology hints and links |
| Username / Email / Social | Public profile references and searchable metadata |
| Breach Intelligence | Public incident disclosure references |
| Exposure Dataset Lab | Redacted CSV ingestion and HMAC-based exposure matching |
| Credential Intelligence | Offline password hygiene and owner-authorized records |
| Evidence Vault | Integrity digest, evidence source and timeline |
| Entity Correlation | Extracted entities and relationships |
| Reports | JSON, HTML and PDF exports |
| Audit Trail | Security-relevant actions and dataset operations |

## Security and Privacy Controls

- No external intelligence-provider API keys are needed.
- HTTPS-only public fetches, no URL-embedded authentication and non-standard ports disabled.
- Hostname resolution checks reject non-global IP addresses.
- robots.txt is consulted for public page fetches.
- Response size, timeout and redirect limits reduce resource abuse and SSRF risk.
- Exposure import rejects sensitive credential columns.
- Imported identifiers are HMACed with a deployment secret; the secret must remain stable.
- Workspace routes require an operator-configured access token for remote deployment.
- Optional credential records are encrypted at rest and reveal events are audited.
- Reports exclude credential plaintext.

## Testing Plan

| Test category | Example validation |
|---|---|
| Unit | Target detection, normalization, HMAC generation, password heuristics |
| API | Investigation creation, target creation, collection jobs, CSV import/matching |
| Negative | Reject password columns, malformed CSV, unsupported file types, private IP targets |
| Authorization | Verify remote requests fail without the access token |
| Evidence | Confirm SHA-256 digests and report exports |
| Frontend | JavaScript syntax validation and manual responsive UI review |
| Deployment | Health endpoint, database connectivity and environment secret checks |

**Automated test command:** `python -m pytest -q`

**Latest development validation:** 25 automated tests passed; Python compilation and JavaScript syntax checks passed. Live third-party source availability is not covered by the mocked/offline test suite and must be tested separately against sources that permit automated access.


## Deployment

Local development uses SQLite. Cloud deployment uses the Vercel Python runtime and must set `DATABASE_URL` to a persistent PostgreSQL database; the app fails startup rather than silently using temporary SQLite on Vercel. Vercel function filesystem writes are temporary; uploaded binary evidence is not durable there without a separate object-storage implementation. Full commands and environment-variable instructions are in the root `README.md`.

## Limitations and Future Work

- HTML source parsers can require maintenance when upstream layouts change.
- Search-result pages can be incomplete, stale or personalized.
- Exposure matching only covers the indexes that the analyst legitimately provides.
- Large collection workloads should use durable queued workers instead of in-process tasks.
- Future research could evaluate parser accuracy, collection coverage, response latency, false-match handling and analyst usability using synthetic ground-truth datasets.
- A full multi-user RBAC model, durable binary object storage and a browser-isolated crawler are potential extensions.

## Conclusion

Cyber X demonstrates an integrated workflow for OSINT investigations and privacy-preserving data-exposure correlation. It combines public-source HTML parsing, DNS posture, redacted dataset analysis, evidence integrity and reporting in one application. Its safety boundary is part of the design: it analyzes authorized, public and analyst-provided redacted information rather than bypassing protected sources or acquiring stolen secrets.

## Suggested Viva Questions

1. Why does the platform use HMAC instead of plain SHA-256 for imported email identifiers?
2. What is the difference between a public HTML scraper and a provider API integration?
3. Why is a public search result a lead instead of proof of a breach?
4. Why must the HMAC secret remain stable across deployments?
5. Why is PostgreSQL preferred over SQLite for a hosted Vercel deployment?
6. What is the purpose of robots.txt checks, public-IP validation and response-size limits?
7. How are evidence integrity and chain-of-custody metadata represented?
8. What are the limitations of in-process background tasks in serverless hosting?

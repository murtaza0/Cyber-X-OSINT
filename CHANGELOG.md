# Changelog

## 2.0.0 — Stateless Live-Collection Release

- Replaced database-backed investigations and collection jobs with a single-target, in-memory scan API.
- Removed database initialization, table creation, source seeding and persistent storage configuration from the runtime entrypoint.
- Added bounded public-source collection with a maximum of eight modules and three concurrent collectors per scan.
- Added JSON and HTML report generation in the browser; reports are not uploaded to the server.
- Removed credential storage, exposure-dataset import and investigation-history workflows from the active UI/API.
- Simplified deployment configuration: no PostgreSQL, DATABASE_URL, credential encryption key or exposure HMAC key is required.
- Kept public-source access boundaries, target validation, collector timeout handling and remote API-token protection.

## 1.5.0 — FYP Exposure Intelligence Release

- Previous database-backed release. See Git history for the archived implementation.

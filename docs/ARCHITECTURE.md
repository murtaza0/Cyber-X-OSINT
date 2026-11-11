# Stateless Architecture Notes

## Request flow

1. The browser submits one target and an optional list of up to eight modules.
2. `app.core.targets.detect_target` classifies and normalizes the target.
3. `app.api.stateless_routes` selects supported public-source modules and runs at most three collectors concurrently.
4. Collector results are normalized in memory and returned in one JSON response.
5. The browser displays findings and creates JSON/HTML exports locally.

## Data handling

- No database engine, ORM session, schema creation, migration, investigation table or job queue is initialized by the active application.
- Target inputs and findings are not persisted by the application.
- JSON/HTML exports are generated in the browser and are not uploaded.
- Vercel temporary storage is not used for scan results.
- The older database-backed modules remain in the repository history/source tree but are not imported by the active FastAPI entrypoint or mounted API router.

## API

- `GET /api/v1/modules`: supported module catalog.
- `POST /api/v1/scan`: one target and up to eight public-source modules.
- `GET /health`: process health and memory-only storage mode.

## Collector contract

Collectors return dictionaries containing module, finding type, value, optional details, source URL, confidence and verification status. An observation should only be described as verified when the source actually supports it. Search references are investigative leads, not proof.

## Security boundaries

- Remote API access requires an operator-configured `API_TOKEN`.
- The scan endpoint accepts one target and caps module count and collector concurrency.
- Collectors use bounded HTTP responses, timeouts, public destination checks and source access-policy handling.
- No authentication bypass, credential dump access, password harvesting, private database connector, CAPTCHA evasion or active port scanning is implemented.
- Add edge/WAF rate limiting and monitor usage before exposing the endpoint broadly. An API token is not multi-user identity or role-based access control.

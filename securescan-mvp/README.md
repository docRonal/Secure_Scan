# SecureScan AI Backend

The backend is a FastAPI service for authenticated asset management, ownership verification, passive security checks, scan orchestration, reports, and recurring monitoring. Optional OWASP ZAP integration provides active scanning and is disabled by default.

## Responsible use and security

- Scan only systems you own or are explicitly authorized to test. Passive checks make real network requests; active scans send test payloads and can affect target systems.
- Active scanning is disabled by default with `ZAP_ENABLED=false`. It also requires OWASP ZAP to be configured and the asset to have verified ownership.
- Set unique, private values for `JWT_SECRET_KEY` and `ZAP_API_KEY`. Never commit local `.env` files or reuse development secrets in a deployment.
- This MVP uses SQLite, an in-process background task mechanism, APScheduler, and a process-local in-memory rate limiter. These are not substitutes for durable, distributed production infrastructure.
- Do not expose the development deployment directly to the public internet. Production use needs network egress controls, TLS, restrictive CORS, durable job processing, distributed rate limiting, and operational monitoring.

## What the scanners do

Passive checks inspect observable responses and records; they do not test SQL injection, XSS, command injection, or other input-driven vulnerabilities. Those require active probes.

When explicitly enabled, OWASP ZAP performs spidering and active tests against verified assets. ZAP's built-in rules provide the attack tests; this repository's integration translates ZAP alerts into SecureScan findings and OWASP categories. See [the active scanning guide](app/scanners/active/README.md).

## Run with Docker Compose

From the repository root:

```bash
cp docker-compose.env.example .env
# Set unique JWT_SECRET_KEY and ZAP_API_KEY values in .env.
docker compose up --build
```

- API and Swagger UI: <http://localhost:8000/docs>
- Dashboard: <http://localhost:8081>

The ZAP service is included in Compose, but active scans remain disabled unless `ZAP_ENABLED=true` is set. See the root [Quick Start](../QUICKSTART.md) for manual setup and more configuration.

## Run the backend manually

From this directory, using Python 3.12:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET_KEY="$(openssl rand -hex 32)"
uvicorn app.main:app --reload --port 8000
```

API documentation is available at <http://127.0.0.1:8000/docs>.

## Authentication and API workflow

Set `AUTH_REQUIRED=false` only for trusted local development. The backend then puts all anonymous requests into one shared guest workspace; visitors can see and modify its assets and start scans. Do not expose this mode to the internet. Hosted deployments should use `AUTH_REQUIRED=true` and provision the bootstrap account with `SEED_ADMIN_ENABLED=true`, `SEED_ADMIN_EMAIL`, and a unique `SEED_ADMIN_PASSWORD` before first startup. Public registration is preserved in code but disabled unless `PUBLIC_REGISTRATION_ENABLED=true`. Synthetic demo data is a separate opt-in through `SEED_DEMO_DATA_ENABLED`. In authenticated mode, all endpoints other than `/auth/*` require `Authorization: Bearer <token>`.

In authenticated mode, sign in and extract the access token:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"operator@example.invalid","password":"your-bootstrap-password"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

Create an asset you own or are authorized to test. Do not use a public example domain as a target without authorization.

```bash
curl -X POST http://127.0.0.1:8000/assets \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"domain":"your-authorized-domain.tld"}'
```

Asset ownership can be verified using DNS TXT, an HTML meta tag, or a file token. Once verified, an active scan may be requested if ZAP is configured and enabled. Passive scans do not require ownership verification, but still make network requests and must only be used with authorized targets.

```bash
# Start a passive scan for asset ID 1.
curl -X POST http://127.0.0.1:8000/scans \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"asset_id":1,"scan_type":"passive"}'

# Check scan status and retrieve a report.
curl http://127.0.0.1:8000/scans/1 -H "Authorization: Bearer $TOKEN"
curl http://127.0.0.1:8000/reports/1 -H "Authorization: Bearer $TOKEN"
curl "http://127.0.0.1:8000/reports/1?format=pdf" \
  -H "Authorization: Bearer $TOKEN" -o report.pdf
curl "http://127.0.0.1:8000/reports/1?format=csv" \
  -H "Authorization: Bearer $TOKEN" -o report.csv
```

Monitoring schedules can be created, listed, paused, resumed, and deleted through `/monitoring`. The scheduler checks due schedules every minute and uses the same scan orchestration path as manual scans. New findings are logged by the MVP notification backend.

## Technology and implementation notes

- **API:** FastAPI, Pydantic, SQLAlchemy
- **Authentication:** JWT with HS256; PBKDF2-HMAC-SHA256 password hashes
- **Database:** SQLite by default
- **Monitoring:** APScheduler and an in-memory sliding-window scan limiter
- **Reports:** JSON, Jinja2 HTML, FPDF2 PDF, and CSV
- **Active scanning:** optional OWASP ZAP REST API integration

The scan rate limit defaults to 20 scan requests per hour per user. Because the limiter is process-local, it resets on restart and is not shared across multiple backend workers.

## Project layout

```text
app/
  main.py                 FastAPI app, middleware, and startup
  config.py               Environment-based settings
  db.py                   SQLAlchemy engine and sessions
  models.py               Database models and Pydantic schemas
  security.py             Password hashing and JWT helpers
  ratelimit.py            Process-local sliding-window limiter
  scheduler.py            APScheduler monitoring loop
  routers/                Auth, assets, scans, reports, monitoring APIs
  verification/           DNS TXT, meta-tag, and file-token checks
  scanners/passive/       Passive security checks
  scanners/active/        Optional OWASP ZAP integration
  orchestrator/           Scan execution and persistence
  monitoring/             Finding comparison
  notifications/          Notification abstraction
  reporting/              JSON, HTML, PDF, and CSV report generation
  vulnerability_db/       NVD CVE lookup client
  assets/fonts/           Fonts bundled for PDF output
tests/                    Backend regression tests
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Passive scanner tests use mocks and do not contact real targets. The MVP test suite covers authentication helpers, domain validation, passive checks, rate limiting, and export/error-handling regressions. Full router, orchestration, and live ZAP integration testing are not currently included.

## Current limitations

The MVP does not include enterprise SSO, billing, cloud misconfiguration scanning, AI-based finding prioritization, Redis-backed rate limiting, or a durable distributed job queue. Review the repository root README for deployment caveats before exposing the service to external users.

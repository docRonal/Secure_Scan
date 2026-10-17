# SecureScan AI Quick Start

This guide covers Docker Compose and manual development setup. Docker Compose is recommended for a consistent local environment.

## Option A: Docker Compose

### Prerequisites

- Docker Engine
- Docker Compose plugin (`docker compose`)

### Configure secrets

From the repository root, copy the template:

```bash
cp docker-compose.env.example .env
```

Set a unique random value for `JWT_SECRET_KEY`; this is always required. `ZAP_API_KEY` may remain blank while `ZAP_ENABLED=false`. If you later enable active scanning, set a separate unique key. Generate secret values with:

```bash
openssl rand -hex 32
```

For local open access, set these values in `.env`:

```dotenv
AUTH_REQUIRED=false
PUBLIC_REGISTRATION_ENABLED=false
SEED_DEMO_DATA_ENABLED=false
```

All visitors to this local stack share the same anonymous workspace and can create scans. Do not expose it to a network or the public internet. To use password-protected access instead, set `AUTH_REQUIRED=true`, then set `SEED_ADMIN_ENABLED=true`, `SEED_ADMIN_EMAIL`, and a unique `SEED_ADMIN_PASSWORD` before the account is first created. Public registration has a separate opt-in flag and should remain disabled unless deliberately required. Keep `.env` private and do not commit it.

### Start the stack

```bash
docker compose up --build
```

The first build may take several minutes.

- Dashboard: <http://localhost:8081>
- Backend API and Swagger UI: <http://localhost:8000/docs>
- ZAP API: bound to localhost on port `8080`

ZAP is available in the Compose stack, but active scanning is disabled by default. To enable it, set `ZAP_ENABLED=true` in `.env`, then restart the backend. Active scans require verified ownership of the asset.

Stop with `Ctrl+C`, then run `docker compose down`. Database data is stored in a Docker volume and survives normal container restarts. `docker compose down -v` also removes that data.

## Option B: Manual development setup

### Backend

Python 3.12 is the version used by the backend Docker image. From the repository root:

```bash
cd securescan-mvp
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET_KEY="$(openssl rand -hex 32)"
export AUTH_REQUIRED=false
export PUBLIC_REGISTRATION_ENABLED=false
export SEED_DEMO_DATA_ENABLED=false
uvicorn app.main:app --reload --port 8000
```

Open <http://127.0.0.1:8000/docs> to inspect the API.

### Dashboard

In a second terminal:

```bash
cd securescan-dashboard
npm ci
VITE_API_URL=http://127.0.0.1:8000 npm run dev
```

Open the address printed by Vite, usually <http://localhost:5173>.

## Create an account and run a passive scan

1. In local open mode, open the dashboard directly. No login is required.
2. Add a domain that you own or are explicitly authorized to test. Do not scan a public site without permission. The reserved `.example` domain is for documentation and synthetic demo data only.
3. Start a passive scan. Passive checks still make network requests to the target.
4. Review the findings and export the report as HTML, PDF, or CSV.

In open mode, all visitors share the same assets and scan reports. Do not use this mode on an untrusted network or a hosted deployment.

## Verify asset ownership

Ownership verification is required for active scanning. In the dashboard, select one of these methods and publish the asset-specific token:

- **DNS TXT:** create a TXT record named `_securescan.<your-domain>` with the token as its value.
- **HTML meta tag:** add `<meta name="securescan-verification" content="TOKEN">` inside the homepage `<head>`.
- **Verification file:** place the token in `securescan-verify.txt` at the website root.

Then use **Verify token placement** in the dashboard.

## Enable active scanning with OWASP ZAP

Active scanning sends real test payloads. Only enable it for systems you own or are explicitly authorized to test, and begin with a staging environment.

### With Docker Compose

Set `ZAP_ENABLED=true` in the root `.env` and restart the backend. The Compose stack already includes ZAP. Verify ownership of the target before starting an active scan.

### With a manually started backend

Start ZAP with a generated key and bind its host port to localhost:

```bash
export ZAP_API_KEY="$(openssl rand -hex 32)"
docker run -u zap -p 127.0.0.1:8080:8080 -i zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true \
  -config api.key="$ZAP_API_KEY"
```

In the backend environment, set:

```bash
export ZAP_ENABLED=true
export ZAP_API_URL=http://127.0.0.1:8080
export ZAP_API_KEY="<the-same-key-used-to-start-zap>"
```

Set `ZAP_API_KEY` to the same value in the backend terminal; environment variables from the ZAP terminal are not automatically shared with another terminal. Restart the backend after setting these variables. See [the ZAP guide](securescan-mvp/app/scanners/active/README.md) for details.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `pip install` fails while building a dependency | Use Python 3.12 or run the backend with Docker Compose. |
| `externally-managed-environment` | Create and activate a virtual environment before installing Python packages. |
| Dashboard stays on the loading screen | Confirm the backend is running and reachable at port `8000`. |
| API requests return 401 after login | The JWT may have expired; sign in again. The default lifetime is seven days. |
| Scan creation returns 429 | The default process-local limit is 20 scans per hour per user. |
| Active scan is unavailable | Verify the asset and confirm `ZAP_ENABLED=true`. |
| ZAP API is unavailable | Check the ZAP container, configured API URL, and matching API key. |
| PDF export fails | Confirm the bundled DejaVu fonts exist under `securescan-mvp/app/assets/fonts/`. |
| Compose reports a missing environment value | Confirm `.env` exists in the repository root and both required secrets are set. |
| A port is already in use | Change the port mapping in `docker-compose.yml`, or use a different Uvicorn port and matching `VITE_API_URL`. |

## More documentation

- [Project overview and technology stack](README.md)
- [Backend API and implementation details](securescan-mvp/README.md)
- [Dashboard details](securescan-dashboard/README.md)
- [OWASP ZAP configuration](securescan-mvp/app/scanners/active/README.md)

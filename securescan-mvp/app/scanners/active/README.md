# Optional Active Scanning with OWASP ZAP

Active scanning is disabled by default. It sends real test payloads to the target and may affect availability or data. Use it only on systems you own or are explicitly authorized to test; start with a staging environment.

Asset ownership must be verified before the backend accepts an active scan. Verification is an authorization check, not a guarantee that the scan is harmless or low impact.

## 1. Start ZAP

For a manually managed backend, start the ZAP container with a unique API key and publish its API only on localhost:

```bash
export ZAP_API_KEY="$(openssl rand -hex 32)"
docker run -u zap -p 127.0.0.1:8080:8080 -i zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true \
  -config api.key="$ZAP_API_KEY"
```

Check that the API is available:

```bash
curl "http://127.0.0.1:8080/JSON/core/view/version/?apikey=$ZAP_API_KEY"
```

The response should contain a ZAP version. Do not expose port `8080` publicly.

When using the repository's Docker Compose setup, ZAP is already included and its host port is bound to `127.0.0.1`.

## 2. Configure the backend

For a manually started backend, set these environment variables before starting Uvicorn. Use the same API key as the ZAP container:

```bash
export ZAP_ENABLED=true
export ZAP_API_URL=http://127.0.0.1:8080
export ZAP_API_KEY="$ZAP_API_KEY"
export ZAP_AJAX_SPIDER_ENABLED=true
```

For Docker Compose, set `ZAP_ENABLED=true` and the same `ZAP_API_KEY` in the repository-root `.env` file. The backend uses the Compose service URL for ZAP.

Without `ZAP_ENABLED=true`, the active scanner plugin is not registered, even if ZAP is running.

## 3. Start or restart the backend

```bash
uvicorn app.main:app --reload --port 8000
```

## 4. Start an active scan

Sign in with the operator-provisioned bootstrap account, add an authorized asset, and complete one of the ownership verification methods first. Then start an active scan from the dashboard or call the API with a bearer token:

```bash
curl -X POST http://127.0.0.1:8000/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"asset_id":1,"scan_type":"active"}'
```

Active scans can take minutes or longer depending on site size and ZAP policy. Poll `GET /scans/{id}` to check progress and status.

## How the integration works

`zap_client.py` calls the ZAP REST API for spidering, optional AJAX Spider discovery, active scanning, and alerts. `zap_scanner.py` maps ZAP alerts to SecureScan findings. The actual test payloads and attack logic are provided by ZAP and are not implemented in this repository.

AJAX Spider is enabled by default with `ZAP_AJAX_SPIDER_ENABLED=true`. If the installed ZAP distribution does not include its add-on, the backend logs a warning and continues with the standard scan.

## Scan policy

ZAP uses its default policy unless `ZAP_SCAN_POLICY` names a policy configured in ZAP. For example:

```bash
ZAP_SCAN_POLICY="My Custom Policy"
```

The backend also supports `ZAP_ATTACK_STRENGTH`, `ZAP_ALERT_THRESHOLD`, and `ZAP_ENABLE_ALL_SCANNERS`. Configure these carefully and review ZAP's policy documentation before scanning sensitive systems.

## Troubleshooting

- **ZAP API unavailable:** check that the container is running and that `ZAP_API_URL` is reachable from the backend. With Compose, use the configured service URL rather than `127.0.0.1` from inside the backend container.
- **ZAP returns 401/403:** confirm `ZAP_API_KEY` matches the key passed to ZAP at startup.
- **Active scan is unavailable:** check `ZAP_ENABLED=true` and verify ownership of the asset.
- **Scan reaches its timeout:** adjust `ZAP_MAX_WAIT_SECONDS` for the size of the authorized target.

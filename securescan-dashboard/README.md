# SecureScan AI Dashboard

The dashboard is a React + TypeScript client for the FastAPI backend in `securescan-mvp/`. It supports password-based login, asset management, ownership verification, passive and active scans, report review and export, and recurring monitoring schedules.

## Development setup

Start the backend first. See the root [Quick Start](../QUICKSTART.md) or [backend README](../securescan-mvp/README.md).

From this directory:

```bash
npm ci
VITE_API_URL=http://127.0.0.1:8000 VITE_AUTH_REQUIRED=false npm run dev
```

Open the URL printed by Vite, usually <http://localhost:5173>. `VITE_API_URL` can be set in a local `.env` file if the backend uses a different address. Do not place secrets in `VITE_*` variables; Vite embeds them in browser-visible assets.

To produce a production build:

```bash
npm run build
```

The Docker image builds the static assets with Vite and serves them through Nginx. The root `docker-compose.yml` configures the browser-facing API URL.

## Main modules

```text
src/
  api.ts                     FastAPI client and authenticated requests
  auth.ts                    JWT storage in localStorage
  types.ts                   Frontend models matching backend schemas
  App.tsx                    Application state and authenticated layout
  i18n.tsx                   English/Russian translations and language switcher
  components/
    LoginScreen.tsx          Sign-in
    Sidebar.tsx              Asset list, asset creation, account menu
    VerificationPanel.tsx    Asset ownership verification methods
    ScanLauncher.tsx         Scan creation, history, and cancellation
    ReportPanel.tsx          Findings, risk score, and report exports
    MonitoringPanel.tsx      Recurring scan schedules
    SeverityBadge.tsx        Finding severity label
    ScanStatusIndicator.tsx  Scan state and progress display
```

## Technology

- React 18 and TypeScript
- Vite for development and production builds
- Tailwind CSS for styling
- Recharts for report visualizations
- Lucide React for icons
- Nginx for serving the production static build

## Security and known limitations

- `VITE_AUTH_REQUIRED=false` opens the dashboard without login; all visitors then share the same guest workspace. Use this only locally. Keep it `true` for hosted deployments.
- Registration UI is hidden by default and can be built with `VITE_PUBLIC_REGISTRATION_ENABLED=true`; the backend must also have `PUBLIC_REGISTRATION_ENABLED=true`.
- JWTs are stored in `localStorage`. A successful cross-site scripting attack could access them; production deployment should consider a stronger browser-session design.
- Report download links pass the access token in a query parameter because browser download links cannot attach the authorization header. Query tokens can be retained in browser history or logs.
- Asset and scan data are refreshed through HTTP polling rather than WebSockets or server-sent events.
- Configure `VITE_API_URL` for the browser's reachable backend address, not a Docker-only service hostname.

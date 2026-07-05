# AIAF Dashboard (frontend)

Vite + React + Tailwind CSS + Recharts single-page dashboard for the AI Assurance
Framework. It consumes the public API and renders the Overview, Adoption Triage,
Risk Analyzer, Governance & Compliance, Model Registry, RAG Inventory, Agent
Authorization, Architecture, and API Explorer tabs — with trend lines,
drift-over-time charts, live auto-refresh (15s polling on live tabs), and a
CycloneDX-backed runtime-component inventory panel in the registry view.

## Develop

```bash
npm install
npm run dev      # http://localhost:5173, proxies /v1 /models /jobs /health to :8000
```

Point the proxy at a non-default API with `AIAF_API_TARGET=http://host:port npm run dev`.

## Build

```bash
npm run build    # compiles into ../src/aiaf/web/ (committed; FastAPI serves it at /)
```

The API key is held in `localStorage` (`aiaf_api_key`, default `dev-key`) and sent
as the `X-API-Key` header on every request; set it from the dashboard header.

## Layout

- `src/api.js` — thin API client (key handling + endpoints).
- `src/useResource.js` — fetch hook with stale-response guarding.
- `src/charts.jsx` — Recharts `TrendLine` and `SeverityBars`.
- `src/ui.jsx` — shared primitives (`Card`, `Metric`, `Pill`, `Tag`, `Empty`).
- `src/App.jsx` — tab shell, API-key control, live auto-refresh.
- `src/tabs/*` — one component per dashboard tab.

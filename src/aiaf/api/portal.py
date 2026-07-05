"""User portal route: serves the single-page operational dashboard.

The dashboard is a Vite + React + Tailwind + Recharts application built into
``src/aiaf/web/`` and served by FastAPI. It consumes the public API (assurance
report, compliance matrix, governance controls, risk analyzer, model registry,
RAG inventory, agent runtime authorization, and architecture catalog) so it
always reflects the running framework's real capabilities — with trend lines,
drift-over-time charts, live auto-refresh, and curated runtime inventory views.

Run ``npm install && npm run build`` in ``frontend/`` to (re)generate the build
output. The compiled assets are mounted at ``/assets`` in ``app.py``.
"""
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["portal"])

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
INDEX_HTML = WEB_DIR / "index.html"
ASSETS_DIR = WEB_DIR / "assets"

_MISSING_BUILD_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AI Assurance Framework</title>
    <style>
      body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
             background: #f4f6f8; color: #18212f; }
      main { width: min(640px, calc(100vw - 32px)); margin: 12vh auto 0; }
      h1 { font-size: 28px; margin: 0 0 12px; }
      p { color: #5f6f83; line-height: 1.6; }
      code { background: #eef4f8; border: 1px solid #d8dee6; border-radius: 6px; padding: 2px 6px;
             font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
      pre { background: #18212f; color: #e7ebf0; padding: 14px 16px; border-radius: 8px; overflow: auto; }
    </style>
  </head>
  <body>
    <main>
      <h1>Dashboard build not found</h1>
      <p>The React dashboard has not been built yet. From the project root, run:</p>
      <pre>cd frontend
npm install
npm run build</pre>
      <p>This compiles the dashboard into <code>src/aiaf/web/</code>, after which this
      page will serve it. The JSON API remains fully available in the meantime.</p>
    </main>
  </body>
</html>
"""


def build_available() -> bool:
    """True when the compiled SPA entrypoint exists."""
    return INDEX_HTML.is_file()


@router.get("/", response_class=HTMLResponse)
def portal_home() -> HTMLResponse:
    """Serve the built single-page dashboard, or a build hint if it is missing."""
    if build_available():
        return HTMLResponse(INDEX_HTML.read_text(encoding="utf-8"))
    return HTMLResponse(_MISSING_BUILD_HTML, status_code=503)

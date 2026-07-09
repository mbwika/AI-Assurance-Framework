# Releasing AIAF Sentry

This document covers the Community package release flow for **AIAF Sentry**.

## Pre-release checks

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
ruff check .
cd frontend && npm ci && npm test && npm run build && cd ..
python -m build
```

## Quick smoke checks

```bash
pip install dist/*.whl
aiaf --help
python -c "from aiaf.api import portal; assert portal.build_available()"
```

## Demo validation

Seed a temporary demo database:

```bash
AIAF_DEMO_DB_PATH=/tmp/aiaf-sentry-demo.db PYTHONPATH=src python scripts/seed_demo_data.py
PYTHONPATH=src python -m aiaf.cli run --host 127.0.0.1 --port 8000
```

Then confirm:

- dashboard loads at `/`
- model inventory is populated
- Governance view shows evidence / snapshots
- RAG Inventory shows at least one trusted and one untrusted document
- Agent Authorization shows allow / approval-required decisions

## Release artifacts

Community release artifacts should include:

- source distribution
- wheel
- release notes / changelog entry
- screenshots or demo assets for announcement

## Public positioning checks

Before announcing a release, confirm that:

- the README quickstart matches the supported install path
- `codensecurity.com/aiaf` messaging matches the current Sentry scope
- Community / Vanguard / Aegis naming is used consistently


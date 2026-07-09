# Contributing to AIAF

Thanks for your interest in improving the AI Assurance Framework. This document
explains how to contribute and the legal terms your contributions are made
under.

## Contributor License Agreement (required)

Before your first contribution can be merged, you must sign the AIAF
Contributor License Agreement ([CLA.md](CLA.md)). The CLA lets the maintainer
accept your contribution, keep the project under the Apache-2.0 license, and
offer the project (including your contribution) under other license terms as
part of AIAF's sustainability model.

Signing is a one-time step per contributor:

- **Individuals** — sign the Individual CLA.
- **On behalf of an employer** — have an authorized signer complete the
  Corporate CLA and list the contributors it covers.

A bot will prompt you to sign on your first pull request. Contributions cannot
be merged until the CLA is signed.

## Developer Certificate of Origin (sign-off)

In addition to the CLA, every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/). Add a
sign-off line to each commit:

```
git commit -s -m "Your message"
```

which appends:

```
Signed-off-by: Your Name <you@example.com>
```

## Development setup

```bash
git clone https://github.com/mbwika/AI-Assurance-Framework.git
cd AI-Assurance-Framework
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # backend + dev tools (pytest, ruff, mypy)

# Run the API locally
PYTHON=python bash scripts/run_local.sh

# Frontend dashboard (separate terminal)
cd frontend && npm install && npm run dev
```

## Before you open a pull request

Run the same checks CI runs — all must pass:

```bash
ruff check .                      # lint (import order, unused imports, etc.)
PYTHONPATH=src python -m pytest -q # full test suite
```

- Keep changes focused; one logical change per PR.
- Add or update tests for any behavior change.
- Match the surrounding code's style, naming, and comment density.
- Do not commit build output, virtualenvs, or secrets (see `.gitignore`).

## Reporting security issues

Do **not** open a public issue for a security vulnerability. Email
security@codensecurity.com with details and a proof of concept. You'll get an
acknowledgement and a coordinated-disclosure timeline.

## Where contributions go

The framework, CLI, API, dashboard, scanner adapters, AI-BOM, evidence, and
standards mappings in this repository are, and remain, Apache-2.0 open source.
The CLA additionally allows the maintainer to build separately-licensed
extensions on top of this core so the project can be sustained; those
extensions live in separate repositories and are not part of this one.

## Repository layout

- `core/` — active analysis engine, parsers, detectors, scoring logic and report generation.
- `web/` — web dashboard and API entrypoints.
- `data/` — runtime-generated data, reports, logs and local persistence.
- `_smieci/` — archive / scratch area for discarded experiments, quick tests and prototype scripts. This directory is not part of the supported runtime or production code path.

The root project folders are the canonical source of truth for MailHunterPro.

---

## Demo / Run locally

Minimum steps to run the web dashboard locally (safe for demos):

1. Create a virtualenv and install requirements:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

2. Start the web dashboard (preferred port 5001):

```bash
MAILHUNTER_PORT=5001 .venv/bin/python web/server.py
# or to force start even if a lockfile exists:
.venv/bin/python web/server.py --force
```

If port 5001 is busy the server will try the next available port in the range 5001..5050 and print the chosen port.

Notes:
- Use `.env.example` as a guide for environment configuration; do not commit real secrets.
- The server creates a runtime lockfile at `data/mailhunter.lock` to prevent accidental multiple instances. Use `--force` to override the lock when you know it's safe.
- Generated reports are stored under `data/reports/` — do not commit those files.

---

This repository is organized for public-facing presentation: `_smieci/` is reserved for archived experiments and scratch work, not active runtime code.

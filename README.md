## Repository layout

- `core/` — active analysis engine, parsers, detectors, scoring logic and report generation.
- `web/` — web dashboard and API entrypoints.
- `data/` — runtime-generated data, reports, logs and local persistence.
- `_smieci/` — archive / scratch area for discarded experiments, quick tests and prototype scripts. This directory is not part of the supported runtime or production code path.

The root project folders are the canonical source of truth for MailHunterPro.

# MailHunterPro

MailHunterPro is an advanced email security analysis toolkit focused on phishing detection, header forensics, URL reputation, brand impersonation, and IOC extraction. It provides CLI and web interfaces for single-file and batch .eml analysis and generates JSON/HTML reports suitable for SOC workflows.

This repository contains the analysis engine and a lightweight web dashboard for local use. It is intended for defensive security research and incident response. Do not use this tool for unauthorized monitoring of other people's data.

---

## Features

- Email parsing and header forensics (SPF/DKIM/DMARC checks)
- IOC extraction (URLs, IPs, domains, hashes) with defanged output
- URL reputation lookups (optional VirusTotal / URLhaus integration)
- Brand impersonation detection (Microsoft, Google, PayPal, etc.)
- Risk scoring (0–100) with detailed breakdown and flags
- Batch .eml directory analysis and JSON/HTML report generation
- Simple web dashboard (Flask) for local use and report browsing
- Honeytoken support: hidden tokens in generated HTML reports to detect unexpected accesses locally
- Config-driven setup with local `config.ini` and encrypted key storage (`mailhunter.key`)

---

## Quick install

Requires Python 3.10+.

1. Clone the repository and create a virtual environment:

```bash
git clone https://github.com/twojlogin/MailHunterPro.git
cd MailHunterPro
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

2. Optional: install stronger phone parsing support:

```bash
.venv/bin/pip install phonenumbers
```

3. Start the web dashboard locally:

```bash
.venv/bin/python web/server.py
# open http://localhost:5001
```

If port 5001 is busy, the server will try the next available port. To force a custom port:

```bash
MAILHUNTER_PORT=8080 .venv/bin/python web/server.py
```

---

## CLI usage

Single file analysis:

```bash
python mailhunter_cli.py analyze suspicious.eml
```

Batch analysis for a directory of emails:

```bash
python mailhunter_cli.py batch ./emails/ --json-output results.json
```

Optional VirusTotal enrichment (requires an API key):

```bash
python mailhunter_cli.py analyze suspicious.eml --vt-key YOUR_API_KEY
```

---

## Reports

Reports are generated as JSON and dark-themed HTML files under `data/reports/` by default. HTML reports include headers, flags, IOC lists, URL reputation, and brand impersonation findings.

Honeytoken behavior: generated HTML reports include an optional hidden resource with a per-report token. If the report is accessed via the local dashboard, the server logs the token, timestamp, request headers and client IP locally in `data/` so you can detect unexpected accesses. This feature is intended for defensive monitoring of your own reports.

---

## Configuration

On first run the tool creates a minimal `config.ini` and an encryption key `mailhunter.key` in the project root. Both are ignored by Git. Keep API keys and credentials local to your environment.

Example `config.ini`:

```ini
[web]
port = 5001
host = 127.0.0.1

[virustotal]
apikey =
```

Large threat feeds and disposable domain lists are supported, but they should be stored locally and referenced by your config or by the relevant detector. Do not commit sensitive feeds or generated data to the repository.

---

## Developer notes

Key modules:

- `core/parser.py` — email parsing
- `core/security_analyzer.py` — scoring rules and suspicious flags
- `core/ioc_extractor.py` — IOC extraction
- `core/report_generator.py` — JSON/HTML report generation and optional honeytoken insertion
- `web/server.py` — Flask dashboard and local honeytoken endpoint
- `core/temp_detector.py` — temporary/disposable email and phone-number detection

Run the automated tests with:

```bash
.venv/bin/python -m pytest tests/ -q
```

---

## Security and privacy

- This tool should be run only on systems you control.
- Logs that may contain IP addresses or User-Agent strings are stored locally only in `data/`.
- Do not use MailHunterPro for unauthorized or invasive monitoring of individuals or third parties.
- URL reputation checks may contact external reputation services if enabled by configuration.

---

## Contributing

Contributions are welcome. Please open issues or pull requests and keep secrets and sensitive data out of the repository.

---

## License

This project is provided under the MIT License. See the `LICENSE` file for details.

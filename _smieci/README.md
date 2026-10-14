# MailHunterPro

Advanced Email Security Analyzer — phishing detection, header forensics, URL reputation, brand impersonation, and IOC extraction.

Created for local security workflows and email investigations.

## Features

- IMAP scanning for Gmail, Outlook, ProtonMail, and other providers
- SPF/DKIM/DMARC analysis
- URL reputation checks
- Brand impersonation detection
- IOC extraction
- Batch .eml analysis
- JSON/HTML reporting
- Tkinter GUI and CLI
- Optional web dashboard

## Setup

```bash
git clone https://github.com/twojlogin/MailHunterPro.git
cd MailHunterPro
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## Project layout

- `core/` — core analysis modules
- `security/` — sandboxing and security helpers
- `utils/` — logging and export utilities
- `scripts/` — environment and sandbox bootstrap scripts
- `web/` — Flask web UI
- `_smieci/` — legacy scratch/test/archival files kept out of normal runtime

## Legacy scratch files

The `_smieci/` directory is kept for archived experiments and legacy notes. It is not part of the main runtime flow. The production requirements source of truth is `requirements.txt` in the project root.

## Usage

### GUI

```bash
python mailhunter_main_gui.py
```

### CLI

```bash
python mailhunter_cli.py analyze suspicious.eml
python mailhunter_cli.py batch ./emails/
```

### Web dashboard

```bash
python web/server.py
```

## Notes

- Use `python configure_accounts.py` to add or manage email accounts.
- Keep `config.ini` and `mailhunter.key` out of source control.
- The project expects Python 3.8+.

"""Strażnik: threat_intel nie może mieć procesów w tle.

Zero crona, zero daemonów, zero auto-startu. Feed pobierany tylko komendą
`python threat_intel.py update` — wtedy i tylko wtedy.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_threat_intel_nie_ma_procesow_w_tle():
    """Brak watch/threading/daemon/cron w threat_intel."""
    zle = []
    src = (ROOT / "core" / "threat_intel.py").read_text(encoding="utf-8")
    for slowo in ("def watch", "threading.Thread", "daemon", "cron",
                  "schedule", "while True:", "time.sleep"):
        if slowo in src:
            zle.append(slowo)
    assert not zle, f"procesy w tle w threat_intel.py: {zle}"

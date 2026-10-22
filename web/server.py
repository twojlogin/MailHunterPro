"""MailHunterPro - Web Dashboard Server"""
import argparse
import json
import os
import signal
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.batch_analyzer import BatchAnalyzer
from core.brand_detector import BrandDetector
from core.config import MailHunterConfig
from core.database import MailHunterDB
from core.header_analyzer import HeaderAnalyzer
from core.ioc_extractor import IOCExtractor
from core.parser import EmailParser
from core.report_generator import ReportGenerator
from core.security_analyzer import SecurityAnalyzer
from core.url_reputation import URLReputation


app = Flask(__name__)
app.secret_key = os.urandom(24)

config = MailHunterConfig()
db = MailHunterDB()
parser = EmailParser()
analyzer = SecurityAnalyzer(config, db)
header_analyzer = HeaderAnalyzer()
ioc_extractor = IOCExtractor()
brand_detector = BrandDetector()
report_generator = ReportGenerator()
url_reputation = URLReputation()

batch_analyzer = BatchAnalyzer(
    parser,
    analyzer,
    header_analyzer,
    ioc_extractor,
    brand_detector,
    report_generator,
    url_reputation,
)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/ping')
def ping():
    """Lightweight health/check endpoint used to detect running MailHunterPro instances."""
    return jsonify({'app': 'MailHunterPro', 'version': '2.0', 'timestamp': datetime.now().isoformat()})


@app.route('/api/stats')
def get_stats():
    stats = db.get_statistics()
    return jsonify(stats)


@app.route('/api/emails')
def get_emails():
    emails = db.get_suspicious_emails(threshold=0)
    return jsonify([
        {
            'id': e[0],
            'sender': e[1],
            'subject': e[2],
            'score': e[3],
            'date': e[4],
            'flags': e[5],
        }
        for e in emails
    ])


@app.route('/api/scan', methods=['POST'])
def scan_email():
    data = request.json or {}
    parsed_email = {
        'headers': data.get('headers', {}),
        'body': data.get('body', {'text': '', 'html': ''}),
        'links': data.get('links', []),
        'attachments': data.get('attachments', []),
        'analysis': {'suspicious_score': 0, 'flags': []},
    }
    result = analyzer.analyze_email(parsed_email)
    return jsonify(result['analysis'])


@app.route('/api/analyze', methods=['POST'])
def analyze_email_full():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename.endswith('.eml'):
        return jsonify({'error': 'Only .eml files supported'}), 400

    import email as email_lib

    msg = email_lib.message_from_bytes(file.read())
    parsed = parser.parse_message(msg)
    if not parsed:
        return jsonify({'error': 'Failed to parse email'}), 400

    analyzed = analyzer.analyze_email(parsed)
    header_result = header_analyzer.analyze(analyzed.get('headers', {}))
    iocs = ioc_extractor.extract_all(analyzed)
    brand_result = brand_detector.analyze(analyzed)

    url_results = {}
    for link in analyzed.get('links', []):
        url = link.get('url', '') if isinstance(link, dict) else ''
        if not url:
            continue
        try:
            res = url_reputation.analyze_url(url)
            if isinstance(res, tuple) and len(res) >= 2:
                url_score, url_findings = res[0], res[1]
            elif isinstance(res, dict):
                url_score = res.get('score', 0)
                url_findings = res.get('findings', [])
            else:
                url_score, url_findings = 0, []
        except Exception:
            url_score, url_findings = 0, []

        url_results[url] = {'score': url_score, 'findings': url_findings}

    combined_score = analyzed['analysis']['suspicious_score']
    try:
        combined_score += header_result[0] if isinstance(header_result, (list, tuple)) else header_result.get('score', 0)
    except Exception:
        pass
    try:
        combined_score += brand_result[0] if isinstance(brand_result, (list, tuple)) else brand_result.get('score', 0)
    except Exception:
        pass

    for url_data in url_results.values():
        combined_score += url_data.get('score', 0)
    analyzed['analysis']['suspicious_score'] = min(combined_score, 100)

    report_json = report_generator.generate_json(analyzed, iocs, header_result, url_results, brand_result)
    report_html = report_generator.generate_html(analyzed, iocs, header_result, url_results, brand_result)

    return jsonify({
        'score': analyzed['analysis']['suspicious_score'],
        'verdict': _get_verdict(analyzed['analysis']['suspicious_score']),
        'flags': analyzed['analysis']['flags'],
        'header_findings': header_result[1] if isinstance(header_result, (list, tuple)) else header_result.get('findings', []),
        'brand_findings': brand_result[1] if isinstance(brand_result, (list, tuple)) else brand_result.get('findings', []),
        'iocs': iocs,
        'report_json': report_json,
        'report_html': report_html,
    })


@app.route('/api/batch', methods=['POST'])
def batch_analyze():
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400

    import tempfile

    temp_dir = tempfile.mkdtemp()
    files = request.files.getlist('files')

    for f in files:
        if f.filename.endswith('.eml'):
            filepath = os.path.join(temp_dir, f.filename)
            f.save(filepath)

    results = batch_analyzer.analyze_directory(temp_dir)
    summary = batch_analyzer.generate_summary(results)

    for r in results:
        r.pop('parsed', None)

    return jsonify({
        'summary': summary,
        'results': [{
            'file': os.path.basename(r['file']),
            'score': r['score'],
            'verdict': r['verdict'],
            'flags': r['flags'],
            'report_html': r['report_html'],
        } for r in results],
    })


@app.route('/api/report/<path:filename>')
def get_report(filename):
    report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'reports')
    available = {}
    if os.path.isdir(report_dir):
        for name in os.listdir(report_dir):
            full = os.path.join(report_dir, name)
            if os.path.isfile(full):
                available[name] = full
    filepath = available.get(os.path.basename(filename))
    if filepath is not None:
        return send_file(filepath)
    return jsonify({'error': 'Report not found'}), 404


@app.route('/api/blacklist', methods=['POST'])
def add_blacklist():
    data = request.json or {}
    db.add_to_blacklist(data['type'], data['value'], data.get('reason', ''))
    return jsonify({'status': 'ok'})


@app.route('/api/whitelist', methods=['POST'])
def add_whitelist():
    data = request.json or {}
    db.add_to_whitelist(data['type'], data['value'], data.get('notes', ''))
    return jsonify({'status': 'ok'})


def _get_verdict(score):
    if score >= 80:
        return 'CRITICAL'
    if score >= 60:
        return 'HIGH'
    if score >= 40:
        return 'MEDIUM'
    if score >= 20:
        return 'LOW'
    return 'CLEAN'


def _create_lock_file(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, 'w', encoding='utf-8') as lock_file:
        lock_file.write(str(os.getpid()))


def _read_lock_file(lock_path: Path):
    try:
        return int(lock_path.read_text(encoding='utf-8').strip())
    except Exception:
        return None


def _is_process_running(pid):
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _is_mailhunter_running(port):
    try:
        import urllib.request as request_lib

        with request_lib.urlopen(f'http://127.0.0.1:{port}/api/ping', timeout=1) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data.get('app') == 'MailHunterPro'
    except Exception:
        return False


def _acquire_runtime_lock(force=False):
    project_root = Path(__file__).resolve().parent.parent
    lock_file = project_root / 'data' / 'mailhunter.lock'
    lock_file.parent.mkdir(parents=True, exist_ok=True)

    pid = _read_lock_file(lock_file)
    if pid is not None and _is_process_running(pid):
        if not force:
            print(f"MailHunterPro już działa na PID {pid}. Nie uruchamiam kolejnej instancji.")
            raise SystemExit(0)
        print(f"--force aktywne: nadpisuję istniejący lock MailHunterPro (PID {pid}).")

    _create_lock_file(lock_file)
    return lock_file


def _remove_runtime_lock(lock_path: Path):
    try:
        if lock_path.exists():
            lock_path.unlink()
    except Exception:
        pass


def _free_port(preferred):
    """Returns preferred port if free, otherwise first available port in the range."""
    for port in range(preferred, preferred + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(('127.0.0.1', port))
            except OSError:
                continue
        return port
    raise SystemExit(f"Brak wolnego portu w zakresie {preferred}-{preferred + 49}")


def _parse_args():
    parser = argparse.ArgumentParser(description='MailHunterPro dashboard')
    parser.add_argument('--port', type=int, default=int(os.environ.get('MAILHUNTER_PORT', '5001')))
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--force', action='store_true', help='Force start even if another MailHunterPro instance is running')
    return parser.parse_args()


if __name__ == '__main__':
    args = _parse_args()
    lock_path = None
    try:
        lock_path = _acquire_runtime_lock(force=args.force)

        _preferred = args.port
        if _is_mailhunter_running(_preferred):
            print(f"MailHunterPro już działa na porcie {_preferred}. Nie uruchamiam kolejnej instancji.")
            sys.exit(0)

        _port = _free_port(_preferred)
        if _port != _preferred:
            print(f"Port {_preferred} zajęty, używam {_port}.")
        else:
            print(f"Uruchamiam MailHunterPro na porcie {_preferred}.")

        print(f"🦅 MailHunterPro Dashboard: http://localhost:{_port}")
        app.run(host=args.host, port=_port, debug=False)
    finally:
        if lock_path is not None:
            _remove_runtime_lock(lock_path)

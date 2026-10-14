"""MailHunterPro - Web Dashboard Server"""
import os
import sys
import json
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_file

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import MailHunterConfig
from core.database import MailHunterDB
from core.parser import EmailParser
from core.security_analyzer import SecurityAnalyzer
from core.header_analyzer import HeaderAnalyzer
from core.url_reputation import URLReputation
from core.ioc_extractor import IOCExtractor
from core.brand_detector import BrandDetector
from core.report_generator import ReportGenerator
from core.batch_analyzer import BatchAnalyzer

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
url_reputation = URLReputation(vt_key=config.get_api_key('virustotal'))

batch_analyzer = BatchAnalyzer(
    parser, analyzer, header_analyzer, ioc_extractor,
    brand_detector, report_generator, url_reputation
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
    return jsonify([{
        'id': e[0], 'sender': e[1], 'subject': e[2],
        'score': e[3], 'date': e[4], 'flags': e[5]
    } for e in emails])


@app.route('/api/scan', methods=['POST'])
def scan_email():
    data = request.json
    parsed_email = {
        'headers': data.get('headers', {}),
        'body': data.get('body', {'text': '', 'html': ''}),
        'links': data.get('links', []),
        'attachments': data.get('attachments', []),
        'analysis': {'suspicious_score': 0, 'flags': []}
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
        url = link.get('url', '')
        if url:
            # url_reputation.analyze_url may return dict or tuple; normalize conservatively
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
    # header_result and brand_result can be tuple/dict — be defensive
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
        'report_html': report_html
    })


@app.route('/api/batch', methods=['POST'])
def batch_analyze():
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400

    import tempfile
    import email as email_lib

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
            'report_html': r['report_html']
        } for r in results]
    })


@app.route('/api/report/<path:filename>')
def get_report(filename):
    report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'reports')
    filepath = os.path.join(report_dir, filename)
    if os.path.exists(filepath):
        return send_file(filepath)
    return jsonify({'error': 'Report not found'}), 404


@app.route('/api/blacklist', methods=['POST'])
def add_blacklist():
    data = request.json
    db.add_to_blacklist(data['type'], data['value'], data.get('reason', ''))
    return jsonify({'status': 'ok'})


@app.route('/api/whitelist', methods=['POST'])
def add_whitelist():
    data = request.json
    db.add_to_whitelist(data['type'], data['value'], data.get('notes', ''))
    return jsonify({'status': 'ok'})


def _get_verdict(score):
    if score >= 80: return 'CRITICAL'
    if score >= 60: return 'HIGH'
    if score >= 40: return 'MEDIUM'
    if score >= 20: return 'LOW'
    return 'CLEAN'


def _free_port(preferred):
    """Zwraca preferred, a jak zajęty — pierwszy wolny od preferred+1.

    Port 5001 bywa zajęty (inny serwer, poprzednie uruchomienie). Zamiast
    wywalać się z 'Address already in use', bierzemy następny wolny i mówimy
    jaki. Port z configa ma pierwszeństwo, więc zachowanie jest przewidywalne.
    """
    import socket
    for port in range(preferred, preferred + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('0.0.0.0', port))
            except OSError:
                continue
        return port
    raise SystemExit(f"Brak wolnego portu w zakresie {preferred}-{preferred + 49}")


if __name__ == '__main__':
    _preferred = int(os.environ.get('MAILHUNTER_PORT', '5001'))

    # If preferred port appears occupied, check whether a MailHunterPro instance
    # is already running there. If so, exit to avoid starting duplicate instances.
    try:
        import urllib.request as _ur
        with _ur.urlopen(f'http://127.0.0.1:{_preferred}/api/ping', timeout=1) as _resp:
            _data = json.loads(_resp.read().decode())
            if _data.get('app') == 'MailHunterPro':
                print(f"MailHunterPro już działa na porcie {_preferred}. Nie uruchamiam kolejnej instancji.")
                sys.exit(0)
    except Exception:
        # Nothing listening on preferred port, or not responsive — proceed
        pass

    _port = _free_port(_preferred)
    if _port != _preferred:
        print(f"Port {_preferred} zajęty, używam {_port}.")
    print(f"🦅 MailHunterPro Dashboard: http://localhost:{_port}")
    app.run(host='0.0.0.0', port=_port, debug=False)

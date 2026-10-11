import json
import os
import logging
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_dir=None):
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'reports')
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_json(self, analyzed_email, iocs=None, header_analysis=None, url_results=None, brand_analysis=None):
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'MailHunterPro',
                'version': '2.0'
            },
            'email': {
                'from': analyzed_email.get('headers', {}).get('From', ''),
                'to': analyzed_email.get('headers', {}).get('To', ''),
                'subject': analyzed_email.get('headers', {}).get('Subject', ''),
                'date': analyzed_email.get('headers', {}).get('Date', ''),
                'message_id': analyzed_email.get('headers', {}).get('Message-ID', '')
            },
            'risk_assessment': {
                'score': analyzed_email.get('analysis', {}).get('suspicious_score', 0),
                'verdict': self._get_verdict(analyzed_email.get('analysis', {}).get('suspicious_score', 0)),
                'flags': analyzed_email.get('analysis', {}).get('flags', [])
            },
            'authentication': self._format_header_analysis(header_analysis),
            'url_reputation': self._format_url_results(url_results),
            'brand_impersonation': self._format_brand_analysis(brand_analysis),
            'iocs': self._format_iocs(iocs),
            'attachments': analyzed_email.get('attachments', []),
            'links': analyzed_email.get('links', [])
        }

        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(str(report)) % 10000}.json"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        return filepath

    def generate_html(self, analyzed_email, iocs=None, header_analysis=None, url_results=None, brand_analysis=None):
        score = analyzed_email.get('analysis', {}).get('suspicious_score', 0)
        verdict = self._get_verdict(score)
        verdict_color = self._get_verdict_color(score)
        flags = analyzed_email.get('analysis', {}).get('flags', [])

        auth_html = self._render_auth_table(header_analysis)
        url_html = self._render_url_table(url_results)
        brand_html = self._render_brand_section(brand_analysis)
        iocs_html = self._render_iocs(iocs)
        flags_html = ''.join(f'<span class="flag">{f}</span>' for f in flags)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MailHunterPro Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 20px; }}
.container {{ max-width: 900px; margin: 0 auto; }}
.header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); border: 1px solid #0f3460; border-radius: 12px; padding: 30px; margin-bottom: 20px; text-align: center; }}
.header h1 {{ color: #e94560; font-size: 28px; margin-bottom: 10px; }}
.header .subtitle {{ color: #888; font-size: 14px; }}
.score-box {{ display: inline-block; padding: 15px 40px; border-radius: 10px; margin: 20px 0; font-size: 36px; font-weight: bold; }}
.score-low {{ background: #1a3d1a; color: #4ade80; border: 2px solid #4ade80; }}
.score-mid {{ background: #3d3d1a; color: #facc15; border: 2px solid #facc15; }}
.score-high {{ background: #3d1a1a; color: #ef4444; border: 2px solid #ef4444; }}
.verdict {{ font-size: 20px; margin-top: 10px; color: {verdict_color}; font-weight: bold; }}
.section {{ background: #111; border: 1px solid #333; border-radius: 10px; padding: 20px; margin-bottom: 15px; }}
.section h2 {{ color: #e94560; margin-bottom: 15px; font-size: 18px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th {{ background: #1a1a2e; color: #e94560; padding: 10px; text-align: left; border-bottom: 2px solid #333; }}
td {{ padding: 10px; border-bottom: 1px solid #222; }}
tr:hover {{ background: #1a1a2e; }}
.flag {{ display: inline-block; background: #e94560; color: white; padding: 3px 10px; border-radius: 15px; margin: 2px; font-size: 12px; }}
.flag-safe {{ background: #4ade80; }}
.ioc-item {{ background: #1a1a2e; border: 1px solid #333; border-radius: 8px; padding: 10px; margin: 5px 0; font-family: monospace; font-size: 13px; word-break: break-all; }}
.footer {{ text-align: center; color: #555; font-size: 12px; margin-top: 30px; padding: 20px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>MailHunterPro Analysis Report</h1>
    <div class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    <div class="score-box score-{self._get_score_class(score)}">{score}/100</div>
    <div class="verdict">{verdict}</div>
  </div>

  <div class="section">
    <h2>Email Headers</h2>
    <table>
      <tr><th>From</th><td>{analyzed_email.get('headers', {}).get('From', 'N/A')}</td></tr>
      <tr><th>To</th><td>{analyzed_email.get('headers', {}).get('To', 'N/A')}</td></tr>
      <tr><th>Subject</th><td>{analyzed_email.get('headers', {}).get('Subject', 'N/A')}</td></tr>
      <tr><th>Date</th><td>{analyzed_email.get('headers', {}).get('Date', 'N/A')}</td></tr>
      <tr><th>Return-Path</th><td>{analyzed_email.get('headers', {}).get('Return-Path', 'N/A')}</td></tr>
      <tr><th>Reply-To</th><td>{analyzed_email.get('headers', {}).get('Reply-To', 'N/A')}</td></tr>
    </table>
  </div>

  <div class="section">
    <h2>Flags</h2>
    {flags_html if flags_html else '<span style="color:#4ade80">No suspicious flags detected</span>'}
  </div>

  {auth_html}
  {url_html}
  {brand_html}
  {iocs_html}

  <div class="footer">
    MailHunterPro v2.0 — Advanced Email Security Analyzer
  </div>
</div>
</body>
</html>"""

        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(str(analyzed_email)) % 10000}.html"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)

        return filepath

    def _get_verdict(self, score):
        if score >= 80: return 'CRITICAL — Malicious'
        if score >= 60: return 'HIGH — Likely phishing'
        if score >= 40: return 'MEDIUM — Suspicious'
        if score >= 20: return 'LOW — Some concerns'
        return 'CLEAN — No issues detected'

    def _get_verdict_color(self, score):
        if score >= 80: return '#ef4444'
        if score >= 60: return '#f97316'
        if score >= 40: return '#facc15'
        if score >= 20: return '#a3e635'
        return '#4ade80'

    def _get_score_class(self, score):
        if score >= 60: return 'high'
        if score >= 30: return 'mid'
        return 'low'

    def _format_header_analysis(self, header_analysis):
        if not header_analysis:
            return {}
        return {
            'total_score': header_analysis[0] if isinstance(header_analysis, tuple) else 0,
            'findings': header_analysis[1] if isinstance(header_analysis, tuple) else []
        }

    def _format_url_results(self, url_results):
        if not url_results:
            return []
        results = []
        if isinstance(url_results, dict):
            for url, data in url_results.items():
                results.append({'url': url, **data})
        elif isinstance(url_results, list):
            results = url_results
        return results

    def _format_brand_analysis(self, brand_analysis):
        if not brand_analysis:
            return {}
        return {
            'total_score': brand_analysis[0] if isinstance(brand_analysis, tuple) else 0,
            'findings': brand_analysis[1] if isinstance(brand_analysis, tuple) else []
        }

    def _format_iocs(self, iocs):
        if not iocs:
            return {}
        return iocs

    def _render_auth_table(self, header_analysis):
        if not header_analysis or not isinstance(header_analysis, tuple):
            return ''
        findings = header_analysis[1] if len(header_analysis) > 1 else []
        if not findings:
            return ''

        rows = ''.join(
            f'<tr><td>{f["type"]}</td><td>{f["weight"]}</td><td>{f["detail"]}</td></tr>'
            for f in findings
        )
        return f"""
  <div class="section">
    <h2>Authentication Analysis</h2>
    <table>
      <tr><th>Finding</th><th>Weight</th><th>Detail</th></tr>
      {rows}
    </table>
  </div>"""

    def _render_url_table(self, url_results):
        if not url_results:
            return ''
        if isinstance(url_results, dict):
            url_results = [{'url': k, **v} for k, v in url_results.items()]
        if not isinstance(url_results, list) or not url_results:
            return ''

        rows = ''
        for item in url_results:
            url = item.get('url', 'N/A')
            malicious = item.get('malicious', 0)
            tag = '🔴' if malicious > 0 else '🟢'
            rows += f'<tr><td>{url[:60]}{"..." if len(url) > 60 else ""}</td><td>{tag}</td><td>{malicious}</td></tr>'

        return f"""
  <div class="section">
    <h2>URL Reputation</h2>
    <table>
      <tr><th>URL</th><th>Status</th><th>Detections</th></tr>
      {rows}
    </table>
  </div>"""

    def _render_brand_section(self, brand_analysis):
        if not brand_analysis or not isinstance(brand_analysis, tuple):
            return ''
        findings = brand_analysis[1] if len(brand_analysis) > 1 else []
        if not findings:
            return ''

        items = ''.join(
            f'<div class="flag">{f["type"]}: {f["brand"]} — {f["detail"]}</div>'
            for f in findings
        )
        return f"""
  <div class="section">
    <h2>Brand Impersonation</h2>
    {items}
  </div>"""

    def _render_iocs(self, iocs):
        if not iocs:
            return ''
        defanged = iocs.get('defanged', [])
        if not defanged:
            return ''

        items = ''.join(
            f'<div class="ioc-item"><strong>{i["type"]}</strong>: {i["defanged"]}</div>'
            for i in defanged
        )
        return f"""
  <div class="section">
    <h2>Extracted IOCs (Defanged)</h2>
    {items}
  </div>"""

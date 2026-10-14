import os
import email
import logging
from datetime import datetime


class BatchAnalyzer:
    def __init__(self, parser, security_analyzer, header_analyzer, ioc_extractor, brand_detector, report_generator, url_reputation=None):
        self.parser = parser
        self.security_analyzer = security_analyzer
        self.header_analyzer = header_analyzer
        self.ioc_extractor = ioc_extractor
        self.brand_detector = brand_detector
        self.report_generator = report_generator
        self.url_reputation = url_reputation
        self.logger = logging.getLogger(__name__)

    def _safe_score(self, value, default=0):
        try:
            if value is None:
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    def _safe_findings(self, result):
        if isinstance(result, tuple) and len(result) > 1:
            findings = result[1]
            return findings if isinstance(findings, list) else []
        if isinstance(result, list):
            return result
        return []

    def _safe_url_result(self, result):
        if isinstance(result, tuple) and len(result) >= 2:
            score, findings = result
            return self._safe_score(score), findings if isinstance(findings, list) else []
        if isinstance(result, dict):
            score = result.get('score', 0)
            findings = result.get('findings', [])
            return self._safe_score(score), findings if isinstance(findings, list) else []
        return self._safe_score(result), []

    def analyze_file(self, eml_path, output_dir=None):
        try:
            with open(eml_path, 'rb') as f:
                msg = email.message_from_binary_file(f)

            parsed = self.parser.parse_message(msg)
            if not parsed:
                return None

            analyzed = self.security_analyzer.analyze_email(parsed)

            header_result = self.header_analyzer.analyze(analyzed.get('headers', {})) if self.header_analyzer else (0, [])
            iocs = self.ioc_extractor.extract_all(analyzed) if self.ioc_extractor else []
            brand_result = self.brand_detector.analyze(analyzed) if self.brand_detector else (0, [])

            url_results = {}
            if self.url_reputation:
                for link in analyzed.get('links', []):
                    url = link.get('url', '')
                    if url:
                        url_score, url_findings = self._safe_url_result(self.url_reputation.analyze_url(url))
                        url_results[url] = {
                            'score': url_score,
                            'findings': url_findings
                        }

            header_score = self._safe_score(header_result[0]) if isinstance(header_result, tuple) and len(header_result) > 0 else 0
            brand_score = self._safe_score(brand_result[0]) if isinstance(brand_result, tuple) and len(brand_result) > 0 else 0

            combined_score = analyzed['analysis']['suspicious_score']
            combined_score += header_score
            combined_score += brand_score
            for url_data in url_results.values():
                combined_score += self._safe_score(url_data.get('score', 0))

            analyzed['analysis']['suspicious_score'] = min(combined_score, 100)
            analyzed['analysis']['header_findings'] = self._safe_findings(header_result)
            analyzed['analysis']['brand_findings'] = self._safe_findings(brand_result)
            analyzed['analysis']['url_results'] = url_results
            analyzed['analysis']['iocs'] = iocs

            report_json = self.report_generator.generate_json(
                analyzed, iocs, header_result, url_results, brand_result
            )
            report_html = self.report_generator.generate_html(
                analyzed, iocs, header_result, url_results, brand_result
            )

            return {
                'file': eml_path,
                'score': analyzed['analysis']['suspicious_score'],
                'verdict': self._get_verdict(analyzed['analysis']['suspicious_score']),
                'flags': analyzed['analysis']['flags'],
                'header_findings': analyzed['analysis']['header_findings'],
                'brand_findings': analyzed['analysis']['brand_findings'],
                'iocs': iocs,
                'report_json': report_json,
                'report_html': report_html,
                'parsed': analyzed
            }

        except Exception as e:
            self.logger.error(f'Błąd analizy pliku {eml_path}: {e}')
            return None

    def analyze_directory(self, directory, extensions=None):
        if extensions is None:
            extensions = ['.eml', '.msg']

        results = []
        eml_files = []

        for root, dirs, files in os.walk(directory):
            for f in files:
                if any(f.lower().endswith(ext) for ext in extensions):
                    eml_files.append(os.path.join(root, f))

        self.logger.info(f'Found {len(eml_files)} email files in {directory}')

        for idx, eml_path in enumerate(eml_files):
            self.logger.info(f'Analyzing {idx + 1}/{len(eml_files)}: {os.path.basename(eml_path)}')
            result = self.analyze_file(eml_path)
            if result:
                results.append(result)

        return results

    def generate_summary(self, results):
        if not results:
            return {'total': 0}

        total = len(results)
        malicious = sum(1 for r in results if r['score'] >= 80)
        suspicious = sum(1 for r in results if 40 <= r['score'] < 80)
        clean = sum(1 for r in results if r['score'] < 40)

        all_flags = {}
        for r in results:
            for flag in r.get('flags', []):
                all_flags[flag] = all_flags.get(flag, 0) + 1

        top_flags = sorted(all_flags.items(), key=lambda x: x[1], reverse=True)[:10]

        summary = {
            'total': total,
            'malicious': malicious,
            'suspicious': suspicious,
            'clean': clean,
            'malicious_pct': round(malicious / total * 100, 1) if total > 0 else 0,
            'top_flags': [{'flag': f, 'count': c} for f, c in top_flags],
            'average_score': round(sum(r['score'] for r in results) / total, 1) if total > 0 else 0,
            'highest_score': max(r['score'] for r in results) if results else 0,
            'generated_at': datetime.now().isoformat()
        }

        return summary

    def _get_verdict(self, score):
        if score >= 80: return 'CRITICAL'
        if score >= 60: return 'HIGH'
        if score >= 40: return 'MEDIUM'
        if score >= 20: return 'LOW'
        return 'CLEAN'

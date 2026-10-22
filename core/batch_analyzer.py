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

    def analyze_file(self, eml_path, output_dir=None):
        try:
            if not eml_path or not os.path.exists(eml_path):
                self.logger.warning(f"File not found: {eml_path}")
                return None

            with open(eml_path, 'rb') as f:
                msg = email.message_from_binary_file(f)

            if msg is None:
                self.logger.warning(f"Could not parse message file: {eml_path}")
                return None

            parsed = self.parser.parse_message(msg) if self.parser else None
            if not parsed:
                return None

            analyzed = self.security_analyzer.analyze_email(parsed) if self.security_analyzer else parsed
            if not analyzed:
                return None

            if not isinstance(analyzed, dict):
                return None

            analysis = analyzed.setdefault('analysis', {})

            header_result = self.header_analyzer.analyze(analysis.get('headers', {})) if self.header_analyzer else (0, [])
            iocs = self.ioc_extractor.extract_all(analyzed) if self.ioc_extractor else {}
            brand_result = self.brand_detector.analyze(analyzed) if self.brand_detector else (0, [])

            url_results = {}
            if self.url_reputation:
                for link in analyzed.get('links', []) or []:
                    url = link.get('url', '') if isinstance(link, dict) else ''
                    if url:
                        try:
                            url_score, url_findings = self.url_reputation.analyze_url(url)
                            url_results[url] = {
                                'score': url_score or 0,
                                'findings': url_findings or []
                            }
                        except Exception as e:
                            self.logger.warning(f"URL reputation failed for {url}: {e}")

            combined_score = analysis.get('suspicious_score', 0) or 0
            if isinstance(header_result, tuple) and len(header_result) > 1:
                combined_score += header_result[0] or 0
            elif isinstance(header_result, dict):
                combined_score += header_result.get('score', 0) or 0

            if isinstance(brand_result, tuple) and len(brand_result) > 1:
                combined_score += brand_result[0] or 0
            elif isinstance(brand_result, dict):
                combined_score += brand_result.get('score', 0) or 0

            for url_data in url_results.values():
                combined_score += url_data.get('score', 0) or 0

            analysis['suspicious_score'] = min(combined_score, 100)

            if isinstance(header_result, tuple) and len(header_result) > 1:
                analysis['header_findings'] = header_result[1] or []
            else:
                analysis['header_findings'] = []

            if isinstance(brand_result, tuple) and len(brand_result) > 1:
                analysis['brand_findings'] = brand_result[1] or []
            else:
                analysis['brand_findings'] = []

            analysis['url_results'] = url_results
            analysis['iocs'] = iocs

            report_json = None
            report_html = None
            try:
                if self.report_generator:
                    report_json = self.report_generator.generate_json(
                        analyzed, iocs, header_result, url_results, brand_result
                    )
                    report_html = self.report_generator.generate_html(
                        analyzed, iocs, header_result, url_results, brand_result
                    )
            except Exception as e:
                self.logger.warning(f"Report generation failed for {eml_path}: {e}")

            result = {
                'file': eml_path,
                'score': analysis.get('suspicious_score', 0),
                'verdict': self._get_verdict(analysis.get('suspicious_score', 0)),
                'flags': analysis.get('flags', []),
                'header_findings': analysis.get('header_findings', []),
                'brand_findings': analysis.get('brand_findings', []),
                'iocs': iocs,
                'report_json': report_json,
                'report_html': report_html,
                'parsed': analyzed
            }

            return result

        except Exception as e:
            self.logger.error(f"Błąd analizy pliku {eml_path}: {e}")
            return None

    def analyze_directory(self, directory, extensions=None):
        if extensions is None:
            extensions = ['.eml', '.msg']

        if not directory or not os.path.isdir(directory):
            self.logger.warning(f"Directory not found: {directory}")
            return []

        results = []
        eml_files = []

        for root, dirs, files in os.walk(directory):
            for f in files:
                if any(f.lower().endswith(ext.lower()) for ext in extensions):
                    eml_files.append(os.path.join(root, f))

        self.logger.info(f"Found {len(eml_files)} email files in {directory}")

        for idx, eml_path in enumerate(eml_files):
            self.logger.info(f"Analyzing {idx + 1}/{len(eml_files)}: {os.path.basename(eml_path)}")
            result = self.analyze_file(eml_path)
            if result:
                results.append(result)

        return results

    def generate_summary(self, results):
        if not results:
            return {'total': 0}

        total = len(results)
        malicious = sum(1 for r in results if r.get('score', 0) >= 80)
        suspicious = sum(1 for r in results if 40 <= r.get('score', 0) < 80)
        clean = sum(1 for r in results if r.get('score', 0) < 40)

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
            'average_score': round(sum(r.get('score', 0) for r in results) / total, 1) if total > 0 else 0,
            'highest_score': max(r.get('score', 0) for r in results) if results else 0,
            'generated_at': datetime.now().isoformat()
        }

        return summary

    def _get_verdict(self, score):
        if score >= 80:
            return 'CRITICAL'
        if score >= 60:
            return 'HIGH'
        if score >= 40:
            return 'MEDIUM'
        if score >= 20:
            return 'LOW'
        return 'CLEAN'

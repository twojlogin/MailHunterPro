import os
import email
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional


class BatchAnalyzer:
    def __init__(
        self,
        parser,
        security_analyzer,
        header_analyzer,
        ioc_extractor,
        brand_detector,
        report_generator,
        url_reputation=None
    ):
        self.parser = parser
        self.security_analyzer = security_analyzer
        self.header_analyzer = header_analyzer
        self.ioc_extractor = ioc_extractor
        self.brand_detector = brand_detector
        self.report_generator = report_generator
        self.url_reputation = url_reputation
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def _normalize_analyzer_result(result: Any) -> Dict[str, Any]:
        """
        Normalizes analyzer return values into a dict with keys:
        - score (numeric)
        - findings (list)
        Accepts:
        - None -> {'score': 0, 'findings': []}
        - tuple (score, findings)
        - dict with 'score' and/or 'findings'
        - scalar -> treated as score
        """
        if result is None:
            return {'score': 0, 'findings': []}
        if isinstance(result, tuple) and len(result) >= 2:
            score, findings = result[0], result[1]
            return {
                'score': score if isinstance(score, (int, float)) else 0,
                'findings': findings if isinstance(findings, list) else []
            }
        if isinstance(result, dict):
            score = result.get('score', 0)
            findings = result.get('findings', [])
            return {
                'score': score if isinstance(score, (int, float)) else 0,
                'findings': findings if isinstance(findings, list) else []
            }
        if isinstance(result, (int, float)):
            return {'score': result, 'findings': []}
        return {'score': 0, 'findings': []}

    def analyze_file(self, eml_path: str, output_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
        try:
            with open(eml_path, 'rb') as f:
                msg = email.message_from_binary_file(f)

            parsed = self.parser.parse_message(msg)
            if not parsed:
                self.logger.warning(f'Parser returned no result for {eml_path}')
                return None

            try:
                analyzed = self.security_analyzer.analyze_email(parsed) or {}
            except Exception as e:
                self.logger.exception(f'Error from security_analyzer for {eml_path}: {e}')
                return None

            analysis = analyzed.setdefault('analysis', {})
            analysis.setdefault('suspicious_score', 0)
            analysis.setdefault('flags', [])

            header_result_raw = None
            try:
                header_result_raw = self.header_analyzer.analyze(analyzed.get('headers', {}))
            except Exception as e:
                self.logger.exception(f'header_analyzer failed for {eml_path}: {e}')
            header_result = self._normalize_analyzer_result(header_result_raw)

            brand_result_raw = None
            try:
                brand_result_raw = self.brand_detector.analyze(analyzed)
            except Exception as e:
                self.logger.exception(f'brand_detector failed for {eml_path}: {e}')
            brand_result = self._normalize_analyzer_result(brand_result_raw)

            try:
                iocs = self.ioc_extractor.extract_all(analyzed) or []
            except Exception as e:
                self.logger.exception(f'ioc_extractor failed for {eml_path}: {e}')
                iocs = []

            url_results: Dict[str, Dict[str, Any]] = {}
            if self.url_reputation:
                for link in analyzed.get('links', []) or []:
                    url = None
                    if isinstance(link, dict):
                        url = link.get('url') or link.get('href')
                    elif isinstance(link, str):
                        url = link
                    if not url:
                        continue
                    try:
                        url_res = self.url_reputation.analyze_url(url)
                        if isinstance(url_res, tuple) and len(url_res) >= 2:
                            url_score, url_findings = url_res[0], url_res[1]
                        elif isinstance(url_res, dict):
                            url_score = url_res.get('score', 0)
                            url_findings = url_res.get('findings', [])
                        else:
                            url_score, url_findings = 0, []
                        if not isinstance(url_findings, list):
                            url_findings = []
                        url_results[url] = {'score': url_score or 0, 'findings': url_findings}
                    except Exception as e:
                        self.logger.exception(f'url_reputation.analyze_url failed for {url} in {eml_path}: {e}')
                        url_results[url] = {'score': 0, 'findings': [], 'error': str(e)}

            combined_score = float(analysis.get('suspicious_score', 0))
            combined_score += float(header_result.get('score', 0))
            combined_score += float(brand_result.get('score', 0))
            combined_score += sum(float(u.get('score', 0)) for u in url_results.values())

            analysis['suspicious_score'] = min(combined_score, 100)
            analysis['header_findings'] = header_result.get('findings', [])
            analysis['brand_findings'] = brand_result.get('findings', [])
            analysis['url_results'] = url_results
            analysis['iocs'] = iocs

            try:
                report_json = self.report_generator.generate_json(analyzed, iocs, header_result, url_results, brand_result)
            except Exception as e:
                self.logger.exception(f'generate_json failed for {eml_path}: {e}')
                report_json = None

            try:
                report_html = self.report_generator.generate_html(analyzed, iocs, header_result, url_results, brand_result)
            except Exception as e:
                self.logger.exception(f'generate_html failed for {eml_path}: {e}')
                report_html = None

            return {
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

        except Exception as e:
            self.logger.exception(f'Błąd analizy pliku {eml_path}: {e}')
            return None

    def analyze_directory(self, directory: str, extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if extensions is None:
            extensions = ['.eml', '.msg']

        results: List[Dict[str, Any]] = []
        eml_files: List[str] = []

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

    def generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not results:
            return {'total': 0}

        total = len(results)
        malicious = sum(1 for r in results if (r.get('score') or 0) >= 80)
        suspicious = sum(1 for r in results if 40 <= (r.get('score') or 0) < 80)
        clean = sum(1 for r in results if (r.get('score') or 0) < 40)

        all_flags: Dict[str, int] = {}
        for r in results:
            for flag in r.get('flags', []):
                all_flags[flag] = all_flags.get(flag, 0) + 1

        top_flags = sorted(all_flags.items(), key=lambda x: x[1], reverse=True)[:10]

        average_score = round(sum((r.get('score') or 0) for r in results) / total, 1) if total > 0 else 0

        summary = {
            'total': total,
            'malicious': malicious,
            'suspicious': suspicious,
            'clean': clean,
            'malicious_pct': round(malicious / total * 100, 1) if total > 0 else 0,
            'top_flags': [{'flag': f, 'count': c} for f, c in top_flags],
            'average_score': average_score,
            'highest_score': max((r.get('score') or 0) for r in results) if results else 0,
            'generated_at': datetime.now().isoformat()
        }

        return summary

    def _get_verdict(self, score: float) -> str:
        if score >= 80:
            return 'CRITICAL'
        if score >= 60:
            return 'HIGH'
        if score >= 40:
            return 'MEDIUM'
        if score >= 20:
            return 'LOW'
        return 'CLEAN'

import re
import logging
from urllib.parse import urlparse

from core.header_analyzer import HeaderAnalyzer
from core.ioc_extractor import IOCExtractor
from core.brand_detector import BrandDetector
from core.tracker_detector import TrackerDetector
from core.prompt_detector import PromptDetector
from core.hidden_content_detector import HiddenContentDetector


class SecurityAnalyzer:
    def __init__(self, config, database):
        self.config = config
        self.database = database
        self.logger = logging.getLogger(__name__)
        self.header_analyzer = HeaderAnalyzer()
        self.ioc_extractor = IOCExtractor()
        self.brand_detector = BrandDetector()
        self.tracker_detector = TrackerDetector()
        self.prompt_detector = PromptDetector()
        self.hidden_detector = HiddenContentDetector()

        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*=',
            r'onclick\s*='
        ]

        self.phishing_keywords = [
            'verify your account', 'confirm your identity', 'urgent action required',
            'suspended account', 'unusual activity', 'click here immediately',
            'your account will be closed', 'update payment', 'prize winner',
            'zweryfikuj konto', 'potwierdź tożsamość', 'pilne działanie',
            'zawieszone konto', 'kliknij natychmiast'
        ]

    def analyze_email(self, parsed_email):
        if not isinstance(parsed_email, dict):
            return None

        parsed_email.setdefault('analysis', {})
        parsed_email['analysis'].setdefault('suspicious_score', 0)
        parsed_email['analysis'].setdefault('flags', [])

        score = 0
        flags = []

        try:
            headers = parsed_email.get('headers', {}) or {}
            body = parsed_email.get('body', {}) or {}
            links = parsed_email.get('links', []) or []
            attachments = parsed_email.get('attachments', []) or []

            sender = headers.get('From', '')
            sender_email = self._extract_email(sender)

            if self.database and hasattr(self.database, 'is_whitelisted') and self.database.is_whitelisted('email', sender_email):
                self.logger.info(f"Nadawca {sender_email} jest na białej liście")
                parsed_email['analysis']['suspicious_score'] = 0
                parsed_email['analysis']['flags'] = ['WHITELISTED']
                return parsed_email

            if self.database and hasattr(self.database, 'is_blacklisted') and self.database.is_blacklisted('email', sender_email):
                score += 50
                flags.append('BLACKLISTED_SENDER')

            try:
                header_score, header_findings = self.header_analyzer.analyze(headers)
                score += header_score
                for f in header_findings:
                    flags.append(f['type'])
            except Exception as e:
                self.logger.warning(f"Header analysis failed: {e}")
                header_findings = []

            try:
                content_score, content_flags = self._analyze_content(body)
                score += content_score
                flags.extend(content_flags)
            except Exception as e:
                self.logger.warning(f"Content analysis failed: {e}")
                content_flags = []

            try:
                link_score, link_flags = self._analyze_links(links)
                score += link_score
                flags.extend(link_flags)
            except Exception as e:
                self.logger.warning(f"Link analysis failed: {e}")
                link_flags = []

            try:
                attachment_score, attachment_flags = self._analyze_attachments(attachments)
                score += attachment_score
                flags.extend(attachment_flags)
            except Exception as e:
                self.logger.warning(f"Attachment analysis failed: {e}")
                attachment_flags = []

            try:
                brand_score, brand_findings = self.brand_detector.analyze(parsed_email)
                score += brand_score
                for f in brand_findings:
                    flags.append(f['type'])
            except Exception as e:
                self.logger.warning(f"Brand analysis failed: {e}")
                brand_findings = []

            try:
                tracker_score, tracker_findings = self.tracker_detector.analyze(parsed_email)
                score += tracker_score
                for f in tracker_findings:
                    flags.append(f['type'])
            except Exception as e:
                self.logger.warning(f"Tracker analysis failed: {e}")
                tracker_findings = []

            try:
                prompt_score, prompt_findings = self.prompt_detector.analyze(parsed_email)
                score += prompt_score
                for f in prompt_findings:
                    flags.append(f['type'])
            except Exception as e:
                self.logger.warning(f"Prompt analysis failed: {e}")
                prompt_findings = []

            try:
                hidden_score, hidden_findings = self.hidden_detector.analyze(parsed_email)
                score += hidden_score
                for f in hidden_findings:
                    flags.append(f['type'])
            except Exception as e:
                self.logger.warning(f"Hidden content analysis failed: {e}")
                hidden_findings = []

            try:
                iocs = self.ioc_extractor.extract_all(parsed_email) or []
            except Exception as e:
                self.logger.warning(f"IOC extraction failed: {e}")
                iocs = []

            score = min(score, 100)
            flags = list(dict.fromkeys(flags))

            parsed_email['analysis']['suspicious_score'] = score
            parsed_email['analysis']['flags'] = flags
            parsed_email['analysis']['header_findings'] = header_findings if 'header_findings' in locals() else []
            parsed_email['analysis']['brand_findings'] = brand_findings if 'brand_findings' in locals() else []
            parsed_email['analysis']['tracker_findings'] = tracker_findings if 'tracker_findings' in locals() else []
            parsed_email['analysis']['prompt_findings'] = prompt_findings if 'prompt_findings' in locals() else []
            parsed_email['analysis']['hidden_findings'] = hidden_findings if 'hidden_findings' in locals() else []
            parsed_email['analysis']['iocs'] = iocs

            if score >= self.config.get_threshold('suspicious_score'):
                self.logger.warning(f"Podejrzana wiadomość! Score: {score}, Flags: {flags}")

            return parsed_email

        except Exception as e:
            self.logger.error(f"Błąd analizy bezpieczeństwa: {str(e)}")
            return parsed_email

    def _analyze_content(self, body):
        score = 0
        flags = []

        if not isinstance(body, dict):
            return score, flags

        content = str(body.get('text', '')) + ' ' + str(body.get('html', ''))
        content_lower = content.lower()

        for pattern in self.xss_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                score += 20
                flags.append('XSS_DETECTED')
                break

        phishing_count = sum(1 for keyword in self.phishing_keywords if keyword in content_lower)
        if phishing_count > 0:
            score += min(phishing_count * 10, 30)
            flags.append(f'PHISHING_KEYWORDS_{phishing_count}')

        base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
        base64_matches = re.findall(base64_pattern, content)
        if len(base64_matches) > 2:
            score += 15
            flags.append('BASE64_PAYLOAD')

        hex_pattern = r'(?:0x)?[0-9a-fA-F]{40,}'
        if re.search(hex_pattern, content):
            score += 10
            flags.append('HEX_PAYLOAD')

        return score, flags

    def _analyze_links(self, links):
        score = 0
        flags = []

        if not isinstance(links, list):
            return score, flags

        for link in links:
            if not isinstance(link, dict):
                continue

            url = str(link.get('url', ''))
            suspicious = bool(link.get('suspicious', False))

            if suspicious:
                score += 10
                flags.append('SUSPICIOUS_LINK')

            try:
                domain = urlparse(url).netloc
                if self.database and hasattr(self.database, 'is_blacklisted') and self.database.is_blacklisted('domain', domain):
                    score += 30
                    flags.append(f'BLACKLISTED_DOMAIN_{domain}')
            except Exception:
                pass

        suspicious_links = [l for l in links if isinstance(l, dict) and bool(l.get('suspicious', False))]
        if len(suspicious_links) > 3:
            score += 10
            flags.append('MULTIPLE_SUSPICIOUS_LINKS')

        return score, flags

    def _analyze_attachments(self, attachments):
        score = 0
        flags = []

        if not isinstance(attachments, list):
            return score, flags

        for attachment in attachments:
            if not isinstance(attachment, dict):
                continue
            if attachment.get('suspicious'):
                score += 30
                flags.append(f"SUSPICIOUS_ATTACHMENT_{attachment.get('filename', 'unknown')}")

        return score, flags

    def _extract_email(self, email_string):
        pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        match = re.search(pattern, email_string or '')
        return match.group(0) if match else ''

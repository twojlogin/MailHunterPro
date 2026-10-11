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
        score = 0
        flags = []

        try:
            sender = parsed_email['headers'].get('From', '')
            sender_email = self._extract_email(sender)

            if self.database.is_whitelisted('email', sender_email):
                self.logger.info(f"Nadawca {sender_email} jest na białej liście")
                parsed_email['analysis']['suspicious_score'] = 0
                parsed_email['analysis']['flags'] = ['WHITELISTED']
                return parsed_email

            if self.database.is_blacklisted('email', sender_email):
                score += 50
                flags.append('BLACKLISTED_SENDER')

            header_score, header_findings = self.header_analyzer.analyze(parsed_email['headers'])
            score += header_score
            for f in header_findings:
                flags.append(f['type'])

            content_score, content_flags = self._analyze_content(parsed_email['body'])
            score += content_score
            flags.extend(content_flags)

            link_score, link_flags = self._analyze_links(parsed_email['links'])
            score += link_score
            flags.extend(link_flags)

            attachment_score, attachment_flags = self._analyze_attachments(parsed_email['attachments'])
            score += attachment_score
            flags.extend(attachment_flags)

            brand_score, brand_findings = self.brand_detector.analyze(parsed_email)
            score += brand_score
            for f in brand_findings:
                flags.append(f['type'])

            tracker_score, tracker_findings = self.tracker_detector.analyze(parsed_email)
            score += tracker_score
            for f in tracker_findings:
                flags.append(f['type'])

            prompt_score, prompt_findings = self.prompt_detector.analyze(parsed_email)
            score += prompt_score
            for f in prompt_findings:
                flags.append(f['type'])

            hidden_score, hidden_findings = self.hidden_detector.analyze(parsed_email)
            score += hidden_score
            for f in hidden_findings:
                flags.append(f['type'])

            iocs = self.ioc_extractor.extract_all(parsed_email)

            score = min(score, 100)

            parsed_email['analysis']['suspicious_score'] = score
            parsed_email['analysis']['flags'] = flags
            parsed_email['analysis']['header_findings'] = header_findings
            parsed_email['analysis']['brand_findings'] = brand_findings
            parsed_email['analysis']['tracker_findings'] = tracker_findings
            parsed_email['analysis']['prompt_findings'] = prompt_findings
            parsed_email['analysis']['hidden_findings'] = hidden_findings
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

        content = body.get('text', '') + ' ' + body.get('html', '')
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

        for link in links:
            if link['suspicious']:
                score += 10
                flags.append('SUSPICIOUS_LINK')

            try:
                domain = urlparse(link['url']).netloc
                if self.database.is_blacklisted('domain', domain):
                    score += 30
                    flags.append(f'BLACKLISTED_DOMAIN_{domain}')
            except:
                pass

        if len([l for l in links if l['suspicious']]) > 3:
            score += 10
            flags.append('MULTIPLE_SUSPICIOUS_LINKS')

        return score, flags

    def _analyze_attachments(self, attachments):
        score = 0
        flags = []

        for attachment in attachments:
            if attachment['suspicious']:
                score += 30
                flags.append(f"SUSPICIOUS_ATTACHMENT_{attachment['filename']}")

        return score, flags

    def _extract_email(self, email_string):
        pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        match = re.search(pattern, email_string)
        return match.group(0) if match else ''

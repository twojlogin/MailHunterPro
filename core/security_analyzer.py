"""
SecurityAnalyzer — fasada bezpieczeństwa emaila.

Łączy istniejące detektory (marka, ukryta treść, trackery, prompt injection,
IOC, reputacja URL) w jedno analyze_email() zwracające wynik 0-100 i flagi.
Testy (tests/test_security_analyzer.py) opisują tę klasę — dotychczas nie było
jej implementacji, więc testy nie przechodziły.
"""
import logging
import re

from core.brand_detector import BrandDetector
from core.hidden_content_detector import HiddenContentDetector
from core.tracker_detector import TrackerDetector
from core.prompt_detector import PromptDetector
from core.ioc_extractor import IOCExtractor
from core.url_reputation import URLReputation


class SecurityAnalyzer:
    def __init__(self, config, db):
        self.config = config
        self.db = db
        self.logger = logging.getLogger(__name__)
        self.brand_detector = BrandDetector()
        self.hidden_content_detector = HiddenContentDetector()
        self.tracker_detector = TrackerDetector()
        self.prompt_detector = PromptDetector()
        self.ioc_extractor = IOCExtractor()
        self.url_reputation = URLReputation(
            vt_key=config.get_api_key('virustotal') if hasattr(config, 'get_api_key') else None
        )

    def analyze_email(self, parsed_email):
        """Analizuj email. Zwraca dict z analysis.suspicious_score (0-100)
        i analysis.flags (lista stringów)."""
        headers = parsed_email.get('headers', {})
        body = parsed_email.get('body', {})
        text = body.get('text', '')
        html = body.get('html', '')
        content = text + ' ' + html
        links = parsed_email.get('links', [])
        attachments = parsed_email.get('attachments', [])

        flags = []
        score = 0

        # Brand spoofing / ukryta treść / trackery / prompt injection —
        # detektory przyjmują parsed_email, nie pojedyncze stringi.
        for detector, flag, pts in (
            (self.brand_detector, 'BRAND_SPOOFING', 25),
            (self.hidden_content_detector, 'HIDDEN_CONTENT', 15),
            (self.tracker_detector, 'TRACKERS', 15),
            (self.prompt_detector, 'PROMPT_INJECTION', 30),
        ):
            try:
                wynik = detector.analyze(parsed_email) or {}
                if wynik.get('suspicious') or wynik.get('spoofed') \
                        or wynik.get('found') or wynik.get('detected') \
                        or wynik.get('trackers'):
                    flags.append(flag)
                    score += pts
            except Exception:
                pass

        # XSS / script tags
        if re.search(r'<script\b', content, re.IGNORECASE):
            flags.append('XSS_SCRIPT')
            score += 25

        # Phishing keywords
        phishing_words = ['verify', 'account', 'suspended', 'urgent', 'click here',
                          'password', 'login', 'bank', 'confirm', 'update']
        phishing_hits = sum(1 for w in phishing_words if w in content.lower())
        if phishing_hits >= 2:
            flags.append('PHISHING_KEYWORDS')
            score += min(phishing_hits * 10, 30)

        # Suspicious links
        for link in links:
            if link.get('suspicious'):
                flags.append('SUSPICIOUS_LINK')
                score += 15
                break

        # URL reputation for links
        for link in links:
            url = link.get('url', '')
            if url:
                try:
                    rep = self.url_reputation.check_url(url)
                    if rep.get('malicious'):
                        flags.append('MALICIOUS_URL')
                        score += 25
                        break
                except Exception:
                    pass

        # Blacklist
        sender = headers.get('From', '')
        if self.db and hasattr(self.db, 'is_blacklisted'):
            try:
                if self.db.is_blacklisted('email', sender):
                    flags.append('BLACKLISTED_SENDER')
                    score += 40
            except Exception:
                pass

        # IOC extraction
        try:
            iocs = self.ioc_extractor.extract_all(parsed_email)
            total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
            if total_iocs > 10:
                score += 10
        except Exception:
            pass

        return {
            'headers': headers,
            'body': body,
            'links': links,
            'attachments': attachments,
            'analysis': {
                'suspicious_score': min(score, 100),
                'flags': flags,
            },
        }

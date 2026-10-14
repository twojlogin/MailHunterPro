import re
import logging
from typing import Optional, List
from urllib.parse import urlparse

LOGGER = logging.getLogger(__name__)

# small sample of disposable domains for demo/testing only
DEFAULT_SAMPLE = {
    'mailinator.com', '10minutemail.com', 'tempmail.com', 'guerrillamail.com',
    'trashmail.com', 'dispostable.com', 'yopmail.com', 'maildrop.cc',
    'fakeinbox.com', 'getairmail.com', 'throwawaymail.com', 'temp-mail.org',
    'sharklasers.com', 'spamgourmet.com', 'noreply.com', 'mailnesia.com',
    'mohmal.com', 'fakemail.net', 'disposablemail.com', 'spambog.com'
}


class TempDetector:
    def __init__(self, feed_path: Optional[str] = None, use_bloom: bool = False):
        self.feed_path = feed_path
        self.use_bloom = use_bloom
        self._domains = set(DEFAULT_SAMPLE)
        if feed_path:
            try:
                with open(feed_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith('#'):
                            self._domains.add(domain)
            except Exception as e:
                LOGGER.warning(f'Could not load disposable domains from {feed_path}: {e}')

    def is_disposable_email(self, email_or_domain: Optional[str]) -> bool:
        if not email_or_domain:
            return False
        try:
            # accept either full email or domain
            if '@' in email_or_domain:
                domain = email_or_domain.split('@')[-1].lower()
            else:
                domain = email_or_domain.lower()
            return domain in self._domains
        except Exception:
            return False

    def extract_phone_numbers(self, text: Optional[str]) -> List[str]:
        """Lightweight phone extractor (no external API). Returns raw matches.
        For full parsing/normalization we recommend the `phonenumbers` package.
        """
        if not text:
            return []
        pattern = re.compile(r'\+?[0-9][0-9\s\-\(\)\.]{6,20}[0-9]')
        matches = set()
        for m in pattern.finditer(text):
            num = re.sub(r'[^0-9+]', '', m.group())
            if 6 <= len(re.sub(r'[^0-9]', '', num)) <= 15:
                matches.add(num)
        return list(matches)

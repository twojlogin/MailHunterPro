import logging
import os
import re
from typing import List, Optional

LOGGER = logging.getLogger(__name__)

DEFAULT_SAMPLE = {
    'mailinator.com', '10minutemail.com', 'tempmail.com', 'guerrillamail.com',
    'trashmail.com', 'dispostable.com', 'yopmail.com', 'maildrop.cc',
    'fakeinbox.com', 'getairmail.com', 'throwawaymail.com', 'temp-mail.org',
    'sharklasers.com', 'spamgourmet.com', 'mailnesia.com', 'mohmal.com',
    'fakemail.net', 'disposablemail.com', 'spambog.com', 'moakt.com',
    'mail1.click', 'mailforspam.com', 'guerillamail.com', 'mail-temp.com'
}


class TempDetector:
    def __init__(self, feed_path: Optional[str] = None):
        self.feed_path = feed_path
        self._domains = set(DEFAULT_SAMPLE)

        if feed_path:
            try:
                with open(feed_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith('#'):
                            self._domains.add(domain)
            except Exception as exc:
                LOGGER.warning(f'Could not load disposable domains from {feed_path}: {exc}')
        else:
            default_file = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'data',
                'disposable_sample.txt'
            )
            if os.path.exists(default_file):
                try:
                    with open(default_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            domain = line.strip().lower()
                            if domain and not domain.startswith('#'):
                                self._domains.add(domain)
                except Exception as exc:
                    LOGGER.warning(f'Could not load disposable sample list: {exc}')

    def is_disposable_email(self, email_or_domain: Optional[str]) -> bool:
        if not email_or_domain:
            return False
        try:
            domain = email_or_domain.lower()
            if '@' in email_or_domain:
                domain = email_or_domain.split('@')[-1].lower()
            return domain in self._domains
        except Exception:
            return False

    def extract_phone_numbers(self, text: Optional[str]) -> List[str]:
        """Extract likely phone numbers from free-form text."""
        if not text:
            return []

        patterns = [
            r'\+?[0-9][0-9\s\-\.\(\)]{6,20}[0-9]',
            r'\b(?:00|\+)?[1-9]\d{8,14}\b'
        ]

        matches = set()
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                value = match.group(0)
                cleaned = re.sub(r'[^0-9+]', '', value)
                digits = re.sub(r'[^0-9]', '', cleaned)
                if 8 <= len(digits) <= 15:
                    matches.add(cleaned)
        return sorted(matches)

import re
import logging
import base64
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class TrackerDetector:
    TRACKING_PIXEL_PATTERNS = [
        r'<img[^>]+width=["\']?1["\']?[^>]+height=["\']?1["\']?',
        r'<img[^>]+height=["\']?1["\']?[^>]+width=["\']?1["\']?',
        r'<img[^>]+style=["\']?[^"\']*visibility:\s*hidden[^"\']*["\']?',
        r'<img[^>]+style=["\']?[^"\']*display:\s*none[^"\']*["\']?',
        r'<img[^>]+style=["\']?[^"\']*opacity:\s*0[^"\']*["\']?',
        r'<div[^>]+style=["\']?[^"\']*visibility:\s*hidden[^"\']*["\']?',
        r'<div[^>]+style=["\']?[^"\']*display:\s*none[^"\']*["\']?',
    ]

    KNOWN_TRACKERS = {
        'google-analytics.com': 'Google Analytics',
        'googletagmanager.com': 'Google Tag Manager',
        'doubleclick.net': 'Google DoubleClick',
        'facebook.com/tr': 'Facebook Pixel',
        'facebook.net': 'Facebook SDK',
        'twitter.com/i/adsct': 'Twitter Pixel',
        'tiktok.com/pixel': 'TikTok Pixel',
        'hotjar.com': 'Hotjar',
        'hotjar.io': 'Hotjar',
        'mixpanel.com': 'Mixpanel',
        'amplitude.com': 'Amplitude',
        'segment.com': 'Segment',
        'segment.io': 'Segment',
        'hubspot.com': 'HubSpot',
        'hs-analytics': 'HubSpot Analytics',
        'pardot.com': 'Pardot',
        'sail-horizon.com': 'Marketo',
        'marketo.com': 'Marketo',
        'leadfeeder.com': 'Leadfeeder',
        'clearbit.com': 'Clearbit',
        'intercom.io': 'Intercom',
        'intercom.com': 'Intercom',
        'drift.com': 'Drift',
        'crisp.chat': 'Crisp',
        'zendesk.com': 'Zendesk',
        'mailchimp.com': 'Mailchimp',
        'list-manage.com': 'Mailchimp',
        'sendgrid.net': 'SendGrid',
        'postmaster': 'Postmaster tracking',
        'open-rate': 'Open rate tracking',
        'pixel.gif': 'Generic tracking pixel',
        'pixel.php': 'Generic tracking pixel',
        'track.php': 'PHP tracking',
        'beacon': 'Tracking beacon',
        'analytics': 'Analytics tracker',
        'tracker': 'Generic tracker',
    }

    SUSPICIOUS_TRACKER_HOSTS = [
        'c.litamin.com',
        'pixel.appreturning.com',
        'tr.snapchat.com',
        'ads.yahoo.com',
        'bat.bing.com',
        'ads.linkedin.com',
        'ads.twitter.com',
    ]

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze(self, parsed_email):
        score = 0
        findings = []

        body_html = parsed_email.get('body', {}).get('html', '')
        body_text = parsed_email.get('body', {}).get('text', '')
        headers = parsed_email.get('headers', {})

        pixel_score, pixel_findings = self._detect_tracking_pixels(body_html)
        score += pixel_score
        findings.extend(pixel_findings)

        beacon_score, beacon_findings = self._detect_beacons(body_html)
        score += beacon_score
        findings.extend(beacon_findings)

        redirect_score, redirect_findings = self._detect_tracking_redirects(body_html, body_text)
        score += redirect_score
        findings.extend(redirect_findings)

        header_score, header_findings = self._detect_tracking_headers(headers)
        score += header_score
        findings.extend(header_findings)

        return min(score, 100), findings

    def _detect_tracking_pixels(self, html):
        score = 0
        findings = []

        if not html:
            return score, findings

        soup = BeautifulSoup(html, 'html.parser')

        for img in soup.find_all('img'):
            attrs = img.attrs
            width = attrs.get('width', '')
            height = attrs.get('height', '')
            style = attrs.get('style', '').lower()
            src = attrs.get('src', '')

            is_1x1 = (str(width) in ['1', '0'] and str(height) in ['1', '0'])
            is_hidden = any(x in style for x in ['visibility:hidden', 'visibility: hidden', 'display:none', 'display: none', 'opacity:0', 'opacity: 0'])

            if is_1x1 or is_hidden:
                tracker_name = self._identify_tracker(src)
                score += 15
                findings.append({
                    'type': 'TRACKING_PIXEL',
                    'weight': 15,
                    'detail': f'Wykryto pixel śledzący: {src[:80]} ({tracker_name})',
                    'url': src
                })

        return score, findings

    def _detect_beacons(self, html):
        score = 0
        findings = []

        if not html:
            return score, findings

        soup = BeautifulSoup(html, 'html.parser')

        for script in soup.find_all('script'):
            src = script.get('src', '')
            text = script.string or ''

            for host, name in self.KNOWN_TRACKERS.items():
                if host in src or host in text:
                    score += 5
                    findings.append({
                        'type': 'TRACKING_SCRIPT',
                        'weight': 5,
                        'detail': f'Script śledzący: {name} ({host})'
                    })
                    break

        for link in soup.find_all('link'):
            href = link.get('href', '')
            for host, name in self.KNOWN_TRACKERS.items():
                if host in href:
                    score += 5
                    findings.append({
                        'type': 'TRACKING_LINK',
                        'weight': 5,
                        'detail': f'Link śledzący: {name} ({host})'
                    })
                    break

        return score, findings

    def _detect_tracking_redirects(self, html, text):
        score = 0
        findings = []

        content = html + ' ' + text

        meta_refresh = re.findall(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=([^"\'>\s]+)', html, re.IGNORECASE)
        for url in meta_refresh:
            score += 20
            findings.append({
                'type': 'META_REFRESH_TRACKING',
                'weight': 20,
                'detail': f'Meta refresh redirect: {url[:80]}'
            })

        js_redirects = re.findall(r'(?:window\.location|location\.href|location\.replace|location\.assign)\s*[\(=]\s*["\']([^"\']+)', html, re.IGNORECASE)
        for url in js_redirects:
            if url.startswith('http'):
                score += 15
                findings.append({
                    'type': 'JS_REDIRECT_TRACKING',
                    'weight': 15,
                    'detail': f'JavaScript redirect: {url[:80]}'
                })

        return score, findings

    def _detect_tracking_headers(self, headers):
        score = 0
        findings = []

        list_unsub = headers.get('List-Unsubscribe', '')
        if list_unsub:
            urls = re.findall(r'<(https?://[^>]+)>', list_unsub)
            for url in urls:
                parsed = urlparse(url)
                if parsed.scheme == 'http' and not any(s in parsed.netloc for s in ['gmail', 'outlook', 'yahoo', 'protonmail']):
                    score += 5
                    findings.append({
                        'type': 'UNSUBSCRIBE_TRACKING',
                        'weight': 5,
                        'detail': f'List-Unsubscribe URL (może zawierać tracking): {url[:80]}'
                    })

        x_mailer = headers.get('X-Mailer', '')
        if x_mailer:
            suspicious_mailers = ['Mailchimp', 'SendGrid', 'Postmark', 'Mandrill', 'Amazon SES']
            for mailer in suspicious_mailers:
                if mailer.lower() in x_mailer.lower():
                    score += 3
                    findings.append({
                        'type': 'TRACKING_MAILER',
                        'weight': 3,
                        'detail': f'X-Mailer wskazuje na serwis śledzący: {x_mailer}'
                    })
                    break

        return score, findings

    def _identify_tracker(self, url):
        if not url:
            return 'Unknown'
        url_lower = url.lower()
        for host, name in self.KNOWN_TRACKERS.items():
            if host in url_lower:
                return name
        return 'Unknown tracker'

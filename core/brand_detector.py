import re
import logging
from urllib.parse import urlparse

class BrandDetector:
    KNOWN_BRANDS = {
        'microsoft': {
            'keywords': ['microsoft', 'outlook', 'office365', 'office 365', 'windows', 'azure', 'teams', 'onedrive', 'sharepoint', 'live.com'],
            'trusted_domains': ['microsoft.com', 'outlook.com', 'office365.com', 'live.com', 'microsoftonline.com', 'azure.com', 'sharepoint.com'],
            'display_names': ['Microsoft', 'Microsoft Account', 'Microsoft Support', 'Microsoft Security', 'Office 365', 'Microsoft Teams', 'OneDrive', 'SharePoint']
        },
        'google': {
            'keywords': ['google', 'gmail', 'googlemail', 'workspace', 'google cloud', 'google drive', 'google docs', 'google meet'],
            'trusted_domains': ['google.com', 'gmail.com', 'googlemail.com', 'googleapis.com', 'google.co', 'google.org', 'youtube.com'],
            'display_names': ['Google', 'Google Account', 'Google Security', 'Google Workspace', 'Google Cloud', 'Gmail Team']
        },
        'apple': {
            'keywords': ['apple', 'icloud', 'itunes', 'apple id', 'apple store', 'apple pay', 'facetime', 'imessage'],
            'trusted_domains': ['apple.com', 'icloud.com', 'me.com', 'mac.com', 'itunes.com'],
            'display_names': ['Apple', 'Apple ID', 'Apple Support', 'Apple Security', 'iCloud', 'iTunes']
        },
        'paypal': {
            'keywords': ['paypal'],
            'trusted_domains': ['paypal.com', 'paypal.co', 'paypal.me'],
            'display_names': ['PayPal', 'PayPal Security', 'PayPal Account', 'PayPal Support']
        },
        'amazon': {
            'keywords': ['amazon', 'aws', 'prime', 'amazon web services'],
            'trusted_domains': ['amazon.com', 'amazon.co', 'amazonaws.com', 'amazon.de', 'amazon.pl', 'primevideo.com'],
            'display_names': ['Amazon', 'Amazon Prime', 'Amazon Security', 'AWS', 'Amazon Account']
        },
        'facebook': {
            'keywords': ['facebook', 'meta', 'instagram', 'whatsapp', 'messenger'],
            'trusted_domains': ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'meta.com'],
            'display_names': ['Facebook', 'Meta', 'Instagram', 'WhatsApp']
        },
        'netflix': {
            'keywords': ['netflix'],
            'trusted_domains': ['netflix.com', 'netflix.net'],
            'display_names': ['Netflix', 'Netflix Account', 'Netflix Security']
        },
        'dhl': {
            'keywords': ['dhl', 'dhl express', 'dhl parcel', 'dhl commerce'],
            'trusted_domains': ['dhl.com', 'dhl.de', 'dhl.pl', 'dhl.express'],
            'display_names': ['DHL', 'DHL Express', 'DHL Parcel', 'DHL Commerce']
        },
        'ups': {
            'keywords': ['ups'],
            'trusted_domains': ['ups.com', 'ups.pl'],
            'display_names': ['UPS', 'UPS Delivery', 'UPS Freight']
        },
        'fedex': {
            'keywords': ['fedex'],
            'trusted_domains': ['fedex.com', 'fedex.pl'],
            'display_names': ['FedEx', 'FedEx Delivery', 'FedEx Express']
        },
        'dpd': {
            'keywords': ['dpd'],
            'trusted_domains': ['dpd.com', 'dpd.pl', 'dpd.de'],
            'display_names': ['DPD', 'DPD Delivery', 'DPD Parcel']
        },
        'ing': {
            'keywords': ['ing bank', 'ing direct'],
            'trusted_domains': ['ing.pl', 'ingdirect.com'],
            'display_names': ['ING Bank', 'ING Direct', 'ING Bank Śląski']
        },
        'pekao': {
            'keywords': ['pekao', 'bank pekao', 'pekao sa'],
            'trusted_domains': ['pekao.pl', 'bankpekao.com'],
            'display_names': ['Bank Pekao', 'Pekao SA', 'Pekao24']
        },
        'santander': {
            'keywords': ['santander'],
            'trusted_domains': ['santander.pl', 'santander.com', 'santander.com.pl'],
            'display_names': ['Santander', 'Santander Bank', 'Santander Consumer Bank']
        },
        'mbank': {
            'keywords': ['mbank'],
            'trusted_domains': ['mbank.pl', 'mBank.pl'],
            'display_names': ['mBank', 'mBank24']
        },
        'allegro': {
            'keywords': ['allegro'],
            'trusted_domains': ['allegro.pl', 'allegro.com.pl'],
            'display_names': ['Allegro', 'Allegro Account', 'Allegro Security']
        },
        'poczta_polska': {
            'keywords': ['poczta polska'],
            'trusted_domains': ['poczta-polska.pl', 'poczta-polska.com.pl'],
            'display_names': ['Poczta Polska']
        },
        'play': {
            'keywords': ['play', 'play online'],
            'trusted_domains': ['play.pl', 'playonline.pl'],
            'display_names': ['Play', 'Play Online', 'Play Mobile']
        },
        'orange': {
            'keywords': ['orange'],
            'trusted_domains': ['orange.pl', 'orange.com'],
            'display_names': ['Orange', 'Orange Polska', 'Orange Mobile']
        },
        't_mobile': {
            'keywords': ['t-mobile', 't mobile'],
            'trusted_domains': ['t-mobile.pl', 't-mobile.com'],
            'display_names': ['T-Mobile', 'T-Mobile Polska']
        },
    }

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze(self, parsed_email):
        score = 0
        findings = []

        from_header = parsed_email.get('headers', {}).get('From', '')
        reply_to = parsed_email.get('headers', {}).get('Reply-To', '')
        body_text = parsed_email.get('body', {}).get('text', '')
        body_html = parsed_email.get('body', {}).get('html', '')
        content = body_text + ' ' + body_html

        display_name = self._extract_display_name(from_header)
        sender_domain = self._extract_domain(from_header)

        brand_from_name = self._check_brand_in_display_name(display_name)
        if brand_from_name:
            if sender_domain and not self._is_trusted_domain(sender_domain, brand_from_name):
                score += 25
                findings.append({
                    'type': 'BRAND_DISPLAY_IMPERSONATION',
                    'weight': 25,
                    'brand': brand_from_name,
                    'detail': f'Nazwa "{display_name}" sugeruje {brand_from_name}, ale nadawca to {sender_domain}'
                })

        brand_from_reply = self._check_brand_in_display_name(self._extract_display_name(reply_to))
        if brand_from_reply:
            reply_domain = self._extract_domain(reply_to)
            if reply_domain and sender_domain and reply_domain != sender_domain:
                score += 20
                findings.append({
                    'type': 'BRAND_REPLYTO_IMPERSONATION',
                    'weight': 20,
                    'brand': brand_from_reply,
                    'detail': f'Reply-To zawiera nazwę {brand_from_reply}, ale domena to {reply_domain}'
                })

        brand_in_body = self._check_brand_in_content(content)
        for brand_name in brand_in_body:
            if sender_domain and not self._is_trusted_domain(sender_domain, brand_name):
                existing = [f for f in findings if f.get('brand') == brand_name]
                if not existing:
                    score += 10
                    findings.append({
                        'type': 'BRAND_BODY_MENTION',
                        'weight': 10,
                        'brand': brand_name,
                        'detail': f'Treść wspomina {brand_name}, ale nadawca ({sender_domain}) nie jest zaufaną domeną'
                    })

        return min(score, 100), findings

    def _extract_display_name(self, header):
        if not header:
            return ''
        match = re.match(r'^"?([^"<]+)"?\s*<', header)
        return match.group(1).strip() if match else ''

    def _extract_domain(self, header):
        if not header:
            return ''
        match = re.search(r'@([\w\.-]+)', header)
        return match.group(1).lower() if match else ''

    def _check_brand_in_display_name(self, display_name):
        if not display_name:
            return None
        name_lower = display_name.lower()
        for brand, info in self.KNOWN_BRANDS.items():
            for dn in info['display_names']:
                if dn.lower() in name_lower:
                    return brand
        return None

    def _is_trusted_domain(self, domain, brand):
        if brand not in self.KNOWN_BRANDS:
            return False
        trusted = self.KNOWN_BRANDS[brand]['trusted_domains']
        return any(domain == t or domain.endswith('.' + t) for t in trusted)

    def _check_brand_in_content(self, content):
        found_brands = set()
        content_lower = content.lower()
        for brand, info in self.KNOWN_BRANDS.items():
            for keyword in info['keywords']:
                if keyword in content_lower:
                    found_brands.add(brand)
                    break
        return found_brands

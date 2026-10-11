import re
import logging
from urllib.parse import urlparse

class HeaderAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze(self, headers):
        score = 0
        findings = []

        spf_score, spf_findings = self._check_spf(headers)
        score += spf_score
        findings.extend(spf_findings)

        dkim_score, dkim_findings = self._check_dkim(headers)
        score += dkim_score
        findings.extend(dkim_findings)

        dmarc_score, dmarc_findings = self._check_dmarc(headers)
        score += dmarc_score
        findings.extend(dmarc_findings)

        sender_score, sender_findings = self._check_sender(headers)
        score += sender_score
        findings.extend(sender_findings)

        return min(score, 100), findings

    def _check_spf(self, headers):
        score = 0
        findings = []
        auth = headers.get('Authentication-Results', '')

        if not auth:
            score += 15
            findings.append({'type': 'SPF_MISSING', 'weight': 15, 'detail': 'Brak nagłówka Authentication-Results'})
            return score, findings

        spf_match = re.search(r'spf[=:]\s*(pass|softfail|fail|none|neutral|permerror|temperror)', auth, re.IGNORECASE)
        if spf_match:
            result = spf_match.group(1).lower()
            if result == 'fail':
                score += 20
                findings.append({'type': 'SPF_FAIL', 'weight': 20, 'detail': 'SPF check FAILED'})
            elif result == 'softfail':
                score += 10
                findings.append({'type': 'SPF_SOFTFAIL', 'weight': 10, 'detail': 'SPF softfail — domena nie autoryzuje serwera'})
            elif result == 'none':
                score += 10
                findings.append({'type': 'SPF_NONE', 'weight': 10, 'detail': 'SPF brak polityki (none)'})
            elif result == 'permerror':
                score += 15
                findings.append({'type': 'SPF_PERMERROR', 'weight': 15, 'detail': 'SPF permanent error'})
            elif result == 'pass':
                findings.append({'type': 'SPF_PASS', 'weight': 0, 'detail': 'SPF check passed'})

        return score, findings

    def _check_dkim(self, headers):
        score = 0
        findings = []
        auth = headers.get('Authentication-Results', '')

        if not auth:
            return score, findings

        dkim_match = re.search(r'dkim[=:]\s*(pass|fail|none|neutral|temperror|permerror|policy|nxdomain|unknown)', auth, re.IGNORECASE)
        if dkim_match:
            result = dkim_match.group(1).lower()
            if result == 'fail':
                score += 15
                findings.append({'type': 'DKIM_FAIL', 'weight': 15, 'detail': 'DKIM signature check FAILED'})
            elif result == 'none':
                score += 10
                findings.append({'type': 'DKIM_NONE', 'weight': 10, 'detail': 'Brak podpisu DKIM'})
            elif result == 'policy':
                score += 15
                findings.append({'type': 'DKIM_POLICY', 'weight': 15, 'detail': 'DKIM policy failure'})
            elif result == 'pass':
                findings.append({'type': 'DKIM_PASS', 'weight': 0, 'detail': 'DKIM check passed'})
        else:
            score += 10
            findings.append({'type': 'DKIM_MISSING', 'weight': 10, 'detail': 'Brak wyniku DKIM w Authentication-Results'})

        return score, findings

    def _check_dmarc(self, headers):
        score = 0
        findings = []
        auth = headers.get('Authentication-Results', '')

        if not auth:
            return score, findings

        dmarc_match = re.search(r'dmarc[=:]\s*(pass|fail|none|bestguessnone|quarantine|reject|temperror|permerror|skipped|unknown)', auth, re.IGNORECASE)
        if dmarc_match:
            result = dmarc_match.group(1).lower()
            if result == 'fail':
                score += 20
                findings.append({'type': 'DMARC_FAIL', 'weight': 20, 'detail': 'DMARC check FAILED — mogelijk spoofs'})
            elif result == 'none':
                score += 10
                findings.append({'type': 'DMARC_NONE', 'weight': 10, 'detail': 'DMARC policy = none (geen bescherming)'})
            elif result == 'pass':
                findings.append({'type': 'DMARC_PASS', 'weight': 0, 'detail': 'DMARC check passed'})
        else:
            if 'dmarc' in auth.lower():
                pass
            else:
                score += 5
                findings.append({'type': 'DMARC_ABSENT', 'weight': 5, 'detail': 'DMARC nie sprawdzony'})

        return score, findings

    def _check_sender(self, headers):
        score = 0
        findings = []

        from_addr = headers.get('From', '')
        return_path = headers.get('Return-Path', '')
        reply_to = headers.get('Reply-To', '')

        from_domain = self._extract_domain(from_addr)
        return_domain = self._extract_domain(return_path)
        reply_domain = self._extract_domain(reply_to)

        if from_domain and return_domain and from_domain != return_domain:
            score += 15
            findings.append({
                'type': 'FROM_RETURNPATH_MISMATCH',
                'weight': 15,
                'detail': f'From domain ({from_domain}) != Return-Path domain ({return_domain})'
            })

        if from_domain and reply_domain and from_domain != reply_domain:
            score += 15
            findings.append({
                'type': 'FROM_REPLYTO_MISMATCH',
                'weight': 15,
                'detail': f'From domain ({from_domain}) != Reply-To domain ({reply_domain})'
            })

        if from_addr and reply_to:
            from_email = self._extract_email(from_addr)
            reply_email = self._extract_email(reply_to)
            if from_email and reply_email and from_email != reply_email:
                score += 10
                findings.append({
                    'type': 'REPLYTO_REDIRECT',
                    'weight': 10,
                    'detail': f'Reply-To ({reply_email}) kieruje inaczej niż From ({from_email})'
                })

        display_name = self._extract_display_name(from_addr)
        if display_name and from_domain:
            brand_match = self._detect_brand_in_name(display_name, from_domain)
            if brand_match:
                score += 20
                findings.append({
                    'type': 'BRAND_IMPERSONATION',
                    'weight': 20,
                    'detail': f'Nazwa wydisplay\'owana zawiera "{brand_match}", ale domena to {from_domain}'
                })

        return score, findings

    def _extract_domain(self, addr):
        if not addr:
            return ''
        email_match = re.search(r'@([\w\.-]+)', addr)
        return email_match.group(1).lower() if email_match else ''

    def _extract_email(self, addr):
        if not addr:
            return ''
        match = re.search(r'[\w\.\-]+@[\w\.\-]+', addr)
        return match.group(0).lower() if match else ''

    def _extract_display_name(self, from_header):
        if not from_header:
            return ''
        match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
        return match.group(1).strip() if match else ''

    def _detect_brand_in_name(self, display_name, sending_domain):
        brands = {
            'microsoft': ['microsoft', 'outlook', 'office365', 'windows', 'azure'],
            'google': ['google', 'gmail', 'googlemail', 'workspace'],
            'apple': ['apple', 'icloud', 'itunes'],
            'paypal': ['paypal'],
            'amazon': ['amazon', 'aws'],
            'facebook': ['facebook', 'meta', 'instagram', 'whatsapp'],
            'netflix': ['netflix'],
            'dhl': ['dhl'],
            'ups': ['ups'],
            'fedex': ['fedex'],
            'dpd': ['dpd'],
            'ing': ['ing bank', 'ing direct'],
            'pekao': ['pekao', 'bank pekao'],
            'santander': ['santander'],
            'mbank': ['mbank'],
            'pkobp': ['pkobp', 'pekao sa'],
            'allegro': ['allegro'],
        }
        trusted_domains = {
            'microsoft.com', 'google.com', 'gmail.com', 'outlook.com',
            'apple.com', 'icloud.com', 'paypal.com', 'amazon.com',
            'facebook.com', 'netflix.com', 'dhl.com', 'ups.com',
            'fedex.com', 'dpd.com', 'ing.pl', 'pekao.pl',
            'santander.pl', 'mbank.pl', 'pkobp.pl', 'allegro.pl',
        }

        if sending_domain in trusted_domains:
            return None

        name_lower = display_name.lower()
        for brand, keywords in brands.items():
            for keyword in keywords:
                if keyword in name_lower:
                    return brand

        return None

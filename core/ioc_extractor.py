import re
import hashlib
import logging
from urllib.parse import urlparse
import base64

class IOCExtractor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def extract_all(self, parsed_email):
        iocs = {
            'urls': [],
            'ips': [],
            'domains': [],
            'emails': [],
            'hashes': [],
            'defanged': []
        }

        body_text = parsed_email.get('body', {}).get('text', '')
        body_html = parsed_email.get('body', {}).get('html', '')
        headers = parsed_email.get('headers', {})
        attachments = parsed_email.get('attachments', [])

        content = body_text + ' ' + body_html

        iocs['urls'] = self._extract_urls(content, headers)
        iocs['ips'] = self._extract_ips(content, headers)
        iocs['domains'] = self._extract_domains(iocs['urls'], content)
        iocs['emails'] = self._extract_emails(content)
        iocs['hashes'] = self._extract_hashes(content)
        iocs['defanged'] = self._defang_all(iocs)

        return iocs

    def _extract_urls(self, content, headers):
        urls = set()
        pattern = re.compile(
            r'https?://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%])+',
            re.IGNORECASE
        )
        for match in pattern.finditer(content):
            url = match.group().rstrip('.,;:!?)>')
            urls.add(url)

        for h in headers.get('Received_Chain', []):
            for match in pattern.finditer(h):
                urls.add(match.group().rstrip('.,;:!?)>'))

        return list(urls)

    def _extract_ips(self, content, headers):
        ips = set()
        ipv4 = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        for match in ipv4.finditer(content):
            ip = match.group()
            if not self._is_private_ip(ip):
                ips.add(ip)

        for ip in headers.get('Received_IPs', []):
            ips.add(ip)

        for h in headers.get('Received_Chain', []):
            for match in ipv4.finditer(h):
                ip = match.group()
                if not self._is_private_ip(ip):
                    ips.add(ip)

        ipv6 = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\b')
        for match in ipv6.finditer(content):
            val = match.group()
            if ':' in val and len(val) > 10:
                ips.add(val)

        return list(ips)

    def _extract_domains(self, urls, content):
        domains = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    domain = parsed.netloc.split(':')[0].lower()
                    if domain:
                        domains.add(domain)
            except:
                pass

        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        for match in domain_pattern.finditer(content):
            domain = match.group().lower()
            if not ip_pattern.match(domain) and '.' in domain:
                tld = domain.split('.')[-1]
                if len(tld) >= 2 and tld.isalpha():
                    domains.add(domain)

        return list(domains)

    def _extract_emails(self, content):
        emails = set()
        pattern = re.compile(r'[\w\.\-]+@[\w\.\-]+\.[a-zA-Z]{2,}')
        for match in pattern.finditer(content):
            emails.add(match.group().lower())
        return list(emails)

    def _extract_hashes(self, content):
        hashes = set()
        md5 = re.compile(r'\b[0-9a-fA-F]{32}\b')
        sha1 = re.compile(r'\b[0-9a-fA-F]{40}\b')
        sha256 = re.compile(r'\b[0-9a-fA-F]{64}\b')

        for match in sha256.finditer(content):
            hashes.add(('SHA256', match.group().lower()))
        for match in sha1.finditer(content):
            h = match.group().lower()
            if not any(h == existing[1] for existing in hashes if existing[0] == 'SHA256'):
                hashes.add(('SHA1', h))
        for match in md5.finditer(content):
            h = match.group().lower()
            if not any(h[:32] == existing[1][:32] for existing in hashes):
                hashes.add(('MD5', h))

        return [{'type': t, 'value': v} for t, v in hashes]

    def _defang_all(self, iocs):
        defanged = []
        for url in iocs.get('urls', []):
            defanged.append({
                'type': 'URL',
                'original': url,
                'defanged': url.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')
            })
        for ip in iocs.get('ips', []):
            defanged.append({
                'type': 'IP',
                'original': ip,
                'defanged': ip.replace('.', '[.]')
            })
        for domain in iocs.get('domains', []):
            defanged.append({
                'type': 'DOMAIN',
                'original': domain,
                'defanged': domain.replace('.', '[.]')
            })
        for email in iocs.get('emails', []):
            defanged.append({
                'type': 'EMAIL',
                'original': email,
                'defanged': email.replace('@', '[at]').replace('.', '[.]')
            })
        return defanged

    def _is_private_ip(self, ip):
        private_ranges = [
            '127.', '10.', '192.168.', '169.254.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
        ]
        return any(ip.startswith(prefix) for prefix in private_ranges)

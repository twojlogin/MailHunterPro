import email
import re
import base64
import quopri
import logging
import json
import time
from datetime import datetime
from email.header import decode_header
from bs4 import BeautifulSoup
from typing import Optional, Dict, Any, List


class EmailParser:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def parse_message(self, email_message) -> Optional[Dict[str, Any]]:
        """Parsuje wiadomość e-mail i zwraca strukturę danych"""
        if email_message is None:
            self.logger.warning('parse_message called with None')
            return None

        try:
            headers = self._parse_headers(email_message)
            body = self._parse_body(email_message)
            attachments = self._parse_attachments(email_message)

            parsed_data: Dict[str, Any] = {
                'headers': headers or {},
                'body': body or {'text': '', 'html': '', 'encoding': 'utf-8'},
                'attachments': attachments or [],
                'links': [],
                'analysis': {
                    'suspicious_score': 0,
                    'flags': [],
                    'timestamp': datetime.now().isoformat()
                }
            }

            # Ekstraktowanie linków z treści (bez crashu przy nieoczekiwanych typach)
            try:
                parsed_data['links'] = self._extract_links(parsed_data['body'])
            except Exception as e:
                self.logger.warning(f'Link extraction failed: {e}')
                parsed_data['links'] = []

            return parsed_data

        except Exception as e:
            self.logger.error(f"Błąd parsowania wiadomości: {str(e)}")
            return None

    def _parse_headers(self, email_message) -> Dict[str, Any]:
        """Parsuje nagłówki wiadomości"""
        headers: Dict[str, Any] = {}

        try:
            # Podstawowe nagłówki
            important_headers = [
                'From', 'To', 'Cc', 'Bcc', 'Subject', 'Date',
                'Message-ID', 'Return-Path', 'Reply-To',
                'Received', 'X-Originating-IP', 'X-Mailer',
                'Authentication-Results', 'DKIM-Signature'
            ]

            for header in important_headers:
                try:
                    value = email_message.get(header, '')
                except Exception:
                    value = ''
                if value:
                    # Dekodowanie nagłówków
                    if header in ['From', 'To', 'Cc', 'Subject']:
                        headers[header] = self._decode_header(value)
                    else:
                        headers[header] = value

            # Analiza nagłówków Received
            try:
                received_headers = email_message.get_all('Received', []) or []
            except Exception:
                received_headers = []

            headers['Received_Chain'] = [str(r) for r in received_headers]
            headers['Received_IPs'] = self._extract_ips_from_received(received_headers)

        except Exception as e:
            self.logger.warning(f'Header parsing failed: {e}')

        return headers

    def _decode_header(self, header_value) -> str:
        """Dekoduje zakodowane nagłówki"""
        try:
            decoded_parts = decode_header(header_value)
            decoded_string = ''

            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    try:
                        if encoding:
                            decoded_string += part.decode(encoding, errors='ignore')
                        else:
                            decoded_string += part.decode('utf-8', errors='ignore')
                    except Exception:
                        decoded_string += part.decode('utf-8', errors='ignore')
                else:
                    decoded_string += str(part)

            return decoded_string
        except Exception as e:
            self.logger.warning(f"Błąd dekodowania nagłówka: {str(e)}")
            return str(header_value)

    def _parse_body(self, email_message) -> Dict[str, Any]:
        """Parsuje treść wiadomości"""
        body_data = {
            'text': '',
            'html': '',
            'encoding': 'utf-8'
        }

        try:
            if getattr(email_message, 'is_multipart', lambda: False)() and email_message.is_multipart():
                # Wiadomość wieloczęściowa
                for part in email_message.walk():
                    try:
                        content_type = part.get_content_type()
                        content_disposition = str(part.get('Content-Disposition', ''))
                    except Exception:
                        continue

                    # Pomiń załączniki
                    if 'attachment' in content_disposition:
                        continue

                    try:
                        payload = part.get_payload(decode=True)
                    except Exception:
                        payload = None

                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            decoded_content = payload.decode(charset, errors='ignore')
                        except Exception:
                            try:
                                decoded_content = payload.decode('utf-8', errors='ignore')
                            except Exception:
                                decoded_content = ''

                        if content_type == 'text/plain':
                            body_data['text'] += decoded_content
                        elif content_type == 'text/html':
                            body_data['html'] += decoded_content
            else:
                # Wiadomość jednoczęściowa
                try:
                    payload = email_message.get_payload(decode=True)
                except Exception:
                    payload = None

                if payload:
                    charset = email_message.get_content_charset() or 'utf-8'
                    try:
                        decoded_content = payload.decode(charset, errors='ignore')
                    except Exception:
                        try:
                            decoded_content = payload.decode('utf-8', errors='ignore')
                        except Exception:
                            decoded_content = ''

                    content_type = getattr(email_message, 'get_content_type', lambda: 'text/plain')()
                    if content_type == 'text/plain':
                        body_data['text'] = decoded_content
                    elif content_type == 'text/html':
                        body_data['html'] = decoded_content

        except Exception as e:
            self.logger.error(f"Błąd parsowania treści: {str(e)}")

        return body_data

    def _parse_attachments(self, email_message) -> List[Dict[str, Any]]:
        """Parsuje załączniki"""
        attachments: List[Dict[str, Any]] = []

        try:
            if getattr(email_message, 'is_multipart', lambda: False)() and email_message.is_multipart():
                for part in email_message.walk():
                    try:
                        content_disposition = str(part.get('Content-Disposition', ''))
                    except Exception:
                        content_disposition = ''

                    if 'attachment' in content_disposition:
                        try:
                            filename = part.get_filename()
                        except Exception:
                            filename = None

                        if filename:
                            try:
                                payload = part.get_payload(decode=True) or b''
                                size = len(payload)
                            except Exception:
                                size = 0

                            attachment_data = {
                                'filename': self._decode_header(filename),
                                'content_type': part.get_content_type() if hasattr(part, 'get_content_type') else '',
                                'size': size,
                                'content_id': part.get('Content-ID', '') if hasattr(part, 'get') else '',
                                'suspicious': False
                            }

                            # Podstawowa analiza bezpieczeństwa załącznika
                            try:
                                attachment_data['suspicious'] = self._is_suspicious_attachment(attachment_data)
                            except Exception:
                                attachment_data['suspicious'] = False

                            attachments.append(attachment_data)

        except Exception as e:
            self.logger.error(f"Błąd parsowania załączników: {str(e)}")

        return attachments

    def _extract_links(self, body_data) -> List[Dict[str, Any]]:
        """Ekstraktuje linki z treści wiadomości"""
        links: List[Dict[str, Any]] = []

        try:
            html = ''
            text = ''
            if isinstance(body_data, dict):
                html = str(body_data.get('html', '') or '')
                text = str(body_data.get('text', '') or '')
            else:
                # Nieoczekiwany format
                body_str = str(body_data)
                text = body_str

            # Linki z HTML
            if html:
                try:
                    soup = BeautifulSoup(html, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        text_label = link.get_text(strip=True) or ''
                        if not href:
                            continue
                        link_data = {
                            'url': href,
                            'text': text_label,
                            'suspicious': self._is_suspicious_link(href, text_label),
                            'type': 'html'
                        }
                        links.append(link_data)
                except Exception as e:
                    self.logger.warning(f"Błąd parsowania linków HTML: {e}")

            # Linki z tekstu
            text_content = text + ' ' + html
            url_pattern = re.compile(r'http[s]?://[\w\-\.%@:/?&=+#~]+')

            seen = set(l.get('url') for l in links if isinstance(l, dict) and l.get('url'))
            for match in url_pattern.finditer(text_content):
                try:
                    url = match.group()
                except Exception:
                    continue
                if not url or len(url) > 2000:
                    continue
                if url in seen:
                    continue
                link_data = {
                    'url': url,
                    'text': url,
                    'suspicious': self._is_suspicious_link(url, url),
                    'type': 'text'
                }
                links.append(link_data)
                seen.add(url)

        except Exception as e:
            self.logger.warning(f"_extract_links failed: {e}")

        return links

    def _extract_ips_from_received(self, received_headers) -> List[str]:
        """Ekstraktuje adresy IP z nagłówków Received"""
        ips: List[str] = []
        try:
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

            for header in received_headers:
                try:
                    found_ips = ip_pattern.findall(str(header))
                    ips.extend(found_ips)
                except Exception:
                    continue

            # Usuwanie duplikatów i prywatnych IP
            unique_ips = list(set(ips))
            public_ips = [ip for ip in unique_ips if not self._is_private_ip(ip)]
            return public_ips
        except Exception as e:
            self.logger.warning(f"_extract_ips_from_received failed: {e}")
            return []

    def _is_private_ip(self, ip) -> bool:
        """Sprawdza czy IP jest prywatny"""
        try:
            private_ranges = [
                '127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
                '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                '172.29.', '172.30.', '172.31.'
            ]
            return any(str(ip).startswith(prefix) for prefix in private_ranges)
        except Exception:
            return False

    def _is_suspicious_attachment(self, attachment) -> bool:
        """Sprawdza czy załącznik jest podejrzany"""
        try:
            suspicious_extensions = [
                '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs',
                '.js', '.jar', '.zip', '.rar', '.7z'
            ]

            filename = str(attachment.get('filename', '')).lower()
            return any(filename.endswith(ext) for ext in suspicious_extensions)
        except Exception:
            return False

    def _is_suspicious_link(self, url, text) -> bool:
        """Sprawdza czy link jest podejrzany"""
        try:
            url = str(url or '')
            text = str(text or '')
            # Ukryte linki - tekst nie pasuje do URL
            if text and text != url:
                # Jeśli tekst sugeruje inny URL niż rzeczywisty
                if 'http' in text.lower() and text.lower() not in url.lower():
                    return True

            # Skrócone linki
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
            if any(short in url.lower() for short in shorteners):
                return True

            # IP jako domena
            ip_pattern = re.compile(r'http[s]?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
            if ip_pattern.match(url):
                return True

            # Podejrzane TLD
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
            if any(url.endswith(tld) for tld in suspicious_tlds):
                return True

            return False
        except Exception:
            return False

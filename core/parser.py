import email
import re
import base64
import quopri
import logging
import json
from datetime import datetime
from email.header import decode_header
from bs4 import BeautifulSoup

class EmailParser:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_message(self, email_message):
        """Parsuje wiadomość e-mail i zwraca strukturę danych"""
        try:
            parsed_data = {
                'headers': self._parse_headers(email_message),
                'body': self._parse_body(email_message),
                'attachments': self._parse_attachments(email_message),
                'links': [],
                'analysis': {
                    'suspicious_score': 0,
                    'flags': [],
                    'timestamp': datetime.now().isoformat()
                }
            }
            
            # Ekstraktowanie linków z treści
            parsed_data['links'] = self._extract_links(parsed_data['body'])
            
            return parsed_data
            
        except Exception as e:
            self.logger.error(f"Błąd parsowania wiadomości: {str(e)}")
            return None
    
    def _parse_headers(self, email_message):
        """Parsuje nagłówki wiadomości"""
        headers = {}
        
        # Podstawowe nagłówki
        important_headers = [
            'From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 
            'Message-ID', 'Return-Path', 'Reply-To',
            'Received', 'X-Originating-IP', 'X-Mailer',
            'Authentication-Results', 'DKIM-Signature'
        ]
        
        for header in important_headers:
            value = email_message.get(header, '')
            if value:
                # Dekodowanie nagłówków
                if header in ['From', 'To', 'Cc', 'Subject']:
                    headers[header] = self._decode_header(value)
                else:
                    headers[header] = value
        
        # Analiza nagłówków Received
        received_headers = email_message.get_all('Received', [])
        headers['Received_Chain'] = [str(r) for r in received_headers]
        headers['Received_IPs'] = self._extract_ips_from_received(received_headers)
        
        return headers
    
    def _decode_header(self, header_value):
        """Dekoduje zakodowane nagłówki"""
        try:
            decoded_parts = decode_header(header_value)
            decoded_string = ''
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_string += part.decode(encoding)
                    else:
                        decoded_string += part.decode('utf-8', errors='ignore')
                else:
                    decoded_string += part
            
            return decoded_string
        except Exception as e:
            self.logger.warning(f"Błąd dekodowania nagłówka: {str(e)}")
            return str(header_value)
    
    def _parse_body(self, email_message):
        """Parsuje treść wiadomości"""
        body_data = {
            'text': '',
            'html': '',
            'encoding': 'utf-8'
        }
        
        try:
            if email_message.is_multipart():
                # Wiadomość wieloczęściowa
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition', ''))
                    
                    # Pomiń załączniki
                    if 'attachment' in content_disposition:
                        continue
                    
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            decoded_content = payload.decode(charset, errors='ignore')
                        except:
                            decoded_content = payload.decode('utf-8', errors='ignore')
                        
                        if content_type == 'text/plain':
                            body_data['text'] += decoded_content
                        elif content_type == 'text/html':
                            body_data['html'] += decoded_content
            else:
                # Wiadomość jednoczęściowa
                payload = email_message.get_payload(decode=True)
                if payload:
                    charset = email_message.get_content_charset() or 'utf-8'
                    try:
                        decoded_content = payload.decode(charset, errors='ignore')
                    except:
                        decoded_content = payload.decode('utf-8', errors='ignore')
                    
                    content_type = email_message.get_content_type()
                    if content_type == 'text/plain':
                        body_data['text'] = decoded_content
                    elif content_type == 'text/html':
                        body_data['html'] = decoded_content
        
        except Exception as e:
            self.logger.error(f"Błąd parsowania treści: {str(e)}")
        
        return body_data
    
    def _parse_attachments(self, email_message):
        """Parsuje załączniki"""
        attachments = []
        
        try:
            if email_message.is_multipart():
                for part in email_message.walk():
                    content_disposition = str(part.get('Content-Disposition', ''))
                    
                    if 'attachment' in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            attachment_data = {
                                'filename': self._decode_header(filename),
                                'content_type': part.get_content_type(),
                                'size': len(part.get_payload(decode=True) or b''),
                                'content_id': part.get('Content-ID', ''),
                                'suspicious': False
                            }
                            
                            # Podstawowa analiza bezpieczeństwa załącznika
                            attachment_data['suspicious'] = self._is_suspicious_attachment(attachment_data)
                            
                            attachments.append(attachment_data)
        
        except Exception as e:
            self.logger.error(f"Błąd parsowania załączników: {str(e)}")
        
        return attachments
    
    def _extract_links(self, body_data):
        """Ekstraktuje linki z treści wiadomości"""
        links = []
        
        # Linki z HTML
        if body_data['html']:
            try:
                soup = BeautifulSoup(body_data['html'], 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    text = link.get_text(strip=True)
                    
                    link_data = {
                        'url': href,
                        'text': text,
                        'suspicious': self._is_suspicious_link(href, text),
                        'type': 'html'
                    }
                    links.append(link_data)
            except Exception as e:
                self.logger.warning(f"Błąd parsowania linków HTML: {str(e)}")
        
        # Linki z tekstu
        text_content = body_data['text'] + ' ' + body_data['html']
        url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        
        for match in url_pattern.finditer(text_content):
            url = match.group()
            link_data = {
                'url': url,
                'text': url,
                'suspicious': self._is_suspicious_link(url, url),
                'type': 'text'
            }
            # Unikanie duplikatów
            if not any(l['url'] == url for l in links):
                links.append(link_data)
        
        return links
    
    def _extract_ips_from_received(self, received_headers):
        """Ekstraktuje adresy IP z nagłówków Received"""
        ips = []
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        for header in received_headers:
            found_ips = ip_pattern.findall(str(header))
            ips.extend(found_ips)
        
        # Usuwanie duplikatów i prywatnych IP
        unique_ips = list(set(ips))
        public_ips = [ip for ip in unique_ips if not self._is_private_ip(ip)]
        
        return public_ips
    
    def _is_private_ip(self, ip):
        """Sprawdza czy IP jest prywatny"""
        private_ranges = [
            '127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
            '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
            '172.29.', '172.30.', '172.31.'
        ]
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def _is_suspicious_attachment(self, attachment):
        """Sprawdza czy załącznik jest podejrzany"""
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs',
            '.js', '.jar', '.zip', '.rar', '.7z'
        ]
        
        filename = attachment['filename'].lower()
        return any(filename.endswith(ext) for ext in suspicious_extensions)
    
    def _is_suspicious_link(self, url, text):
        """Sprawdza czy link jest podejrzany"""
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

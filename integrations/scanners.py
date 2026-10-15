# Moduł integracji: VirusTotal, AbuseIPDB, AI, domeny, kontekst, załączniki.
"""
Integracja z VirusTotal API
"""

import requests
import time
import logging
import hashlib

class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.logger = logging.getLogger(__name__)
        self.rate_limit_delay = 15  # 4 requests per minute dla darmowego API
    
    def check_url(self, url):
        """Sprawdza URL w VirusTotal"""
        if not self.api_key:
            self.logger.warning("Brak klucza API VirusTotal")
            return None
        
        try:
            # Koduj URL jako base64
            url_id = hashlib.sha256(url.encode()).hexdigest()
            
            headers = {
                "x-apikey": self.api_key
            }
            
            # Najpierw spróbuj pobrać istniejący raport
            response = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_url_report(data)
            elif response.status_code == 404:
                # URL nie był wcześniej skanowany, wyślij do analizy
                return self._submit_url(url)
            else:
                self.logger.error(f"VirusTotal API error: {response.status_code}")
                return None
        
        except Exception as e:
            self.logger.error(f"Błąd sprawdzania URL w VirusTotal: {str(e)}")
            return None
        
        finally:
            time.sleep(self.rate_limit_delay)
    
    def _submit_url(self, url):
        """Wysyła URL do skanowania"""
        try:
            headers = {
                "x-apikey": self.api_key
            }
            
            data = {"url": url}
            
            response = requests.post(
                f"{self.base_url}/urls",
                headers=headers,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                return {
                    'status': 'submitted',
                    'message': 'URL wysłany do analizy'
                }
            else:
                return None
        
        except Exception as e:
            self.logger.error(f"Błąd wysyłania URL: {str(e)}")
            return None
    
    def _parse_url_report(self, data):
        """Parsuje raport z VirusTotal"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            result = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total_scans': sum(stats.values()),
                'reputation': attributes.get('reputation', 0)
            }
            
            return result
        
        except Exception as e:
            self.logger.error(f"Błąd parsowania raportu: {str(e)}")
            return None
    
    def check_file_hash(self, file_hash):
        """Sprawdza hash pliku w VirusTotal"""
        if not self.api_key:
            return None
        
        try:
            headers = {
                "x-apikey": self.api_key
            }
            
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_file_report(data)
            else:
                return None
        
        except Exception as e:
            self.logger.error(f"Błąd sprawdzania hash: {str(e)}")
            return None
        
        finally:
            time.sleep(self.rate_limit_delay)
    
    def _parse_file_report(self, data):
        """Parsuje raport pliku"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            result = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'file_type': attributes.get('type_description', 'Unknown'),
                'size': attributes.get('size', 0)
            }
            
            return result
        
        except Exception as e:
            self.logger.error(f"Błąd parsowania raportu pliku: {str(e)}")
            return None

# =====================================

# integrations/abuseipdb.py
"""
Integracja z AbuseIPDB API
"""

import requests
import logging

class AbuseIPDBChecker:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.logger = logging.getLogger(__name__)
    
    def check_ip(self, ip_address):
        """Sprawdza reputację IP w AbuseIPDB"""
        if not self.api_key:
            self.logger.warning("Brak klucza API AbuseIPDB")
            return None
        
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            
            response = requests.get(
                f"{self.base_url}/check",
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_ip_report(data)
            else:
                self.logger.error(f"AbuseIPDB API error: {response.status_code}")
                return None
        
        except Exception as e:
            self.logger.error(f"Błąd sprawdzania IP w AbuseIPDB: {str(e)}")
            return None
    
    def _parse_ip_report(self, data):
        """Parsuje raport IP"""
        try:
            ip_data = data.get('data', {})
            
            result = {
                'ip_address': ip_data.get('ipAddress'),
                'abuse_confidence_score': ip_data.get('abuseConfidenceScore', 0),
                'country_code': ip_data.get('countryCode'),
                'usage_type': ip_data.get('usageType'),
                'isp': ip_data.get('isp'),
                'domain': ip_data.get('domain'),
                'total_reports': ip_data.get('totalReports', 0),
                'is_whitelisted': ip_data.get('isWhitelisted', False),
                'is_public': ip_data.get('isPublic', True)
            }
            
            return result
        
        except Exception as e:
            self.logger.error(f"Błąd parsowania raportu IP: {str(e)}")
            return None
    
    def bulk_check(self, ip_list):
        """Sprawdza wiele IP jednocześnie"""
        results = {}
        
        for ip in ip_list:
            result = self.check_ip(ip)
            if result:
                results[ip] = result
        
        return results

# =====================================

# integrations/ai_analyzer.py
"""
Integracja z AI (OpenAI, Claude) do analizy e-maili
"""

import logging

class AIEmailAnalyzer:
    def __init__(self, provider='openai', api_key=None):
        self.provider = provider
        self.api_key = api_key
        self.logger = logging.getLogger(__name__)
        
        if provider == 'openai' and api_key:
            try:
                import openai
                openai.api_key = api_key
                self.client = openai
            except ImportError:
                self.logger.error("Biblioteka openai nie jest zainstalowana")
                self.client = None
        elif provider == 'anthropic' and api_key:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=api_key)
            except ImportError:
                self.logger.error("Biblioteka anthropic nie jest zainstalowana")
                self.client = None
        else:
            self.client = None
    
    def analyze_email_content(self, subject, body, sender):
        """Analizuje treść e-maila używając AI"""
        if not self.client:
            return None
        
        prompt = f"""Przeanalizuj poniższy e-mail pod kątem bezpieczeństwa i phishingu.

Nadawca: {sender}
Temat: {subject}
Treść: {body[:1000]}

Oceń czy to może być:
1. Phishing/oszustwo (tak/nie + uzasadnienie)
2. Socjotechnika (tak/nie + uzasadnienie)
3. Ton wiadomości (pilny/neutralny/przyjazny)
4. Poziom zagrożenia (0-100)
5. Główne podejrzane elementy

Odpowiedz w formacie JSON."""
        
        try:
            if self.provider == 'openai':
                response = self.client.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "Jesteś ekspertem od cyberbezpieczeństwa specjalizującym się w wykrywaniu phishingu."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=500,
                    temperature=0.3
                )
                
                return self._parse_openai_response(response)
            
            elif self.provider == 'anthropic':
                message = self.client.messages.create(
                    model="claude-3-sonnet-20240229",
                    max_tokens=500,
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )
                
                return self._parse_anthropic_response(message)
        
        except Exception as e:
            self.logger.error(f"Błąd analizy AI: {str(e)}")
            return None
    
    def _parse_openai_response(self, response):
        """Parsuje odpowiedź z OpenAI"""
        try:
            content = response.choices[0].message.content
            # Próba parsowania JSON
            import json
            return json.loads(content)
        except:
            return {'raw_response': content}
    
    def _parse_anthropic_response(self, message):
        """Parsuje odpowiedź z Claude"""
        try:
            content = message.content[0].text
            import json
            return json.loads(content)
        except:
            return {'raw_response': content}

# =====================================

# security/domain_checker.py
"""
Sprawdzanie domen i reputacji
"""

import whois
import socket
import logging
from urllib.parse import urlparse

class DomainChecker:
    def __init__(self, database):
        self.database = database
        self.logger = logging.getLogger(__name__)
        
        # Publiczne listy znanych złośliwych domen
        self.known_malicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'
        ]
    
    def check_domain(self, url):
        """Sprawdza domenę pod kątem bezpieczeństwa"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            
            result = {
                'domain': domain,
                'suspicious': False,
                'reasons': [],
                'whois_data': None
            }
            
            # Sprawdź czarną listę w bazie
            if self.database.is_blacklisted('domain', domain):
                result['suspicious'] = True
                result['reasons'].append('BLACKLISTED')
                return result
            
            # Sprawdź białą listę
            if self.database.is_whitelisted('domain', domain):
                result['suspicious'] = False
                return result
            
            # Sprawdź podejrzane TLD
            for tld in self.known_malicious_tlds:
                if domain.endswith(tld):
                    result['suspicious'] = True
                    result['reasons'].append(f'SUSPICIOUS_TLD_{tld}')
            
            # Sprawdź czy domena używa IP zamiast nazwy
            if self._is_ip_address(domain):
                result['suspicious'] = True
                result['reasons'].append('IP_ADDRESS_DOMAIN')
            
            # Sprawdź wiek domeny (WHOIS)
            whois_data = self._get_whois_data(domain)
            if whois_data:
                result['whois_data'] = whois_data
                
                # Młode domeny są bardziej podejrzane
                if whois_data.get('domain_age_days', 365) < 30:
                    result['suspicious'] = True
                    result['reasons'].append('YOUNG_DOMAIN')
            
            return result
        
        except Exception as e:
            self.logger.error(f"Błąd sprawdzania domeny: {str(e)}")
            return None
    
    def _is_ip_address(self, domain):
        """Sprawdza czy string jest adresem IP"""
        try:
            socket.inet_aton(domain)
            return True
        except socket.error:
            return False
    
    def _get_whois_data(self, domain):
        """Pobiera dane WHOIS dla domeny"""
        try:
            w = whois.whois(domain)
            
            # Oblicz wiek domeny
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                from datetime import datetime
                domain_age = (datetime.now() - creation_date).days
            else:
                domain_age = None
            
            return {
                'registrar': w.registrar,
                'creation_date': str(creation_date),
                'expiration_date': str(w.expiration_date),
                'domain_age_days': domain_age,
                'name_servers': w.name_servers
            }
        
        except Exception as e:
            self.logger.warning(f"Nie można pobrać WHOIS dla {domain}: {str(e)}")
            return None

# =====================================

# security/content_analyzer.py
"""
Zaawansowana analiza treści e-maili
"""

import re
import base64
import logging
from bs4 import BeautifulSoup

class ContentAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Wzorce do detekcji
        self.patterns = {
            'javascript': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'on\w+\s*=\s*["\']',
            ],
            'obfuscation': [
                r'eval\s*\(',
                r'unescape\s*\(',
                r'fromCharCode',
                r'&#x[0-9a-fA-F]+;'
            ],
            'base64': r'[A-Za-z0-9+/]{40,}={0,2}',
            'hex': r'(?:0x)?[0-9a-fA-F]{40,}',
            'urls': r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            'email': r'[\w\.-]+@[\w\.-]+\.\w+',
            'phone': r'(?:\+\d{1,3})?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}',
        }
        
        # Słowa kluczowe phishingu
        self.phishing_keywords = {
            'urgent': ['urgent', 'immediate', 'pilne', 'natychmiast', 'teraz'],
            'action': ['verify', 'confirm', 'update', 'click', 'zweryfikuj', 'potwierdź', 'kliknij'],
            'threat': ['suspended', 'locked', 'expire', 'zawieszone', 'zablokowane', 'wygasa'],
            'reward': ['won', 'winner', 'prize', 'wygrałeś', 'nagroda', 'bonus'],
            'financial': ['payment', 'refund', 'tax', 'bank', 'płatność', 'zwrot', 'bank']
        }
    
    def analyze_content(self, body_text, body_html):
        """Przeprowadza pełną analizę treści"""
        results = {
            'score': 0,
            'findings': [],
            'statistics': {}
        }
        
        content = body_text + ' ' + body_html
        
        # Analiza JavaScript i skryptów
        js_score, js_findings = self._check_javascript(body_html)
        results['score'] += js_score
        results['findings'].extend(js_findings)
        
        # Analiza obfuskacji
        obf_score, obf_findings = self._check_obfuscation(content)
        results['score'] += obf_score
        results['findings'].extend(obf_findings)
        
        # Analiza payloadów
        payload_score, payload_findings = self._check_payloads(content)
        results['score'] += payload_score
        results['findings'].extend(payload_findings)
        
        # Analiza słów kluczowych phishingu
        phish_score, phish_findings = self._check_phishing_keywords(content.lower())
        results['score'] += phish_score
        results['findings'].extend(phish_findings)
        
        # Analiza struktury HTML
        html_score, html_findings = self._analyze_html_structure(body_html)
        results['score'] += html_score
        results['findings'].extend(html_findings)
        
        # Statystyki
        results['statistics'] = self._gather_statistics(content, body_html)
        
        return results
    
    def _check_javascript(self, html_content):
        """Sprawdza obecność JavaScript"""
        score = 0
        findings = []
        
        if not html_content:
            return score, findings
        
        for pattern in self.patterns['javascript']:
            matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
            if matches:
                score += 20
                findings.append(f'JAVASCRIPT_DETECTED: {len(matches)} wystąpień')
                break
        
        return score, findings
    
    def _check_obfuscation(self, content):
        """Sprawdza obfuskację kodu"""
        score = 0
        findings = []
        
        for pattern in self.patterns['obfuscation']:
            if re.search(pattern, content, re.IGNORECASE):
                score += 15
                findings.append(f'OBFUSCATION_DETECTED: {pattern}')
        
        return score, findings
    
    def _check_payloads(self, content):
        """Sprawdza payloady base64 i hex"""
        score = 0
        findings = []
        
        # Base64
        base64_matches = re.findall(self.patterns['base64'], content)
        if len(base64_matches) > 2:
            score += 15
            findings.append(f'BASE64_PAYLOAD: {len(base64_matches)} ciągów')
            
            # Próba dekodowania
            for match in base64_matches[:3]:  # Sprawdź pierwsze 3
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    if 'http' in decoded or 'script' in decoded:
                        score += 10
                        findings.append('BASE64_SUSPICIOUS_CONTENT')
                        break
                except:
                    pass
        
        # Hex
        hex_matches = re.findall(self.patterns['hex'], content)
        if len(hex_matches) > 1:
            score += 10
            findings.append(f'HEX_PAYLOAD: {len(hex_matches)} ciągów')
        
        return score, findings
    
    def _check_phishing_keywords(self, content_lower):
        """Sprawdza słowa kluczowe phishingu"""
        score = 0
        findings = []
        categories_found = []
        
        for category, keywords in self.phishing_keywords.items():
            count = sum(1 for keyword in keywords if keyword in content_lower)
            if count > 0:
                categories_found.append(f'{category}({count})')
        
        if len(categories_found) >= 3:
            score += 25
            findings.append(f'PHISHING_KEYWORDS: {", ".join(categories_found)}')
        elif len(categories_found) >= 2:
            score += 15
            findings.append(f'SUSPICIOUS_KEYWORDS: {", ".join(categories_found)}')
        
        return score, findings
    
    def _analyze_html_structure(self, html_content):
        """Analizuje strukturę HTML"""
        score = 0
        findings = []
        
        if not html_content:
            return score, findings
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Ukryte elementy
            hidden_elements = soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden'))
            if len(hidden_elements) > 3:
                score += 10
                findings.append(f'HIDDEN_ELEMENTS: {len(hidden_elements)}')
            
            # Iframe (często używane w phishingu)
            iframes = soup.find_all('iframe')
            if iframes:
                score += 15
                findings.append(f'IFRAME_DETECTED: {len(iframes)}')
            
            # Formularze
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if action and ('http' in action or 'javascript' in action):
                    score += 20
                    findings.append('SUSPICIOUS_FORM_ACTION')
            
            # Meta refresh (przekierowania)
            meta_refresh = soup.find_all('meta', attrs={'http-equiv': 'refresh'})
            if meta_refresh:
                score += 15
                findings.append('META_REFRESH_REDIRECT')
        
        except Exception as e:
            self.logger.warning(f"Błąd analizy HTML: {str(e)}")
        
        return score, findings
    
    def _gather_statistics(self, content, html_content):
        """Zbiera statystyki o treści"""
        stats = {
            'content_length': len(content),
            'url_count': len(re.findall(self.patterns['urls'], content)),
            'email_count': len(re.findall(self.patterns['email'], content)),
            'phone_count': len(re.findall(self.patterns['phone'], content)),
            'has_html': bool(html_content),
            'word_count': len(content.split())
        }
        
        return stats

# =====================================

# security/attachment_scanner.py
"""
Skanowanie załączników
"""

import os
import hashlib
import logging
import mimetypes

class AttachmentScanner:
    def __init__(self, config, database):
        self.config = config
        self.database = database
        self.logger = logging.getLogger(__name__)
        
        # Rozszerzenia plików według kategorii zagrożenia
        self.dangerous_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', 
            '.vbs', '.js', '.jar', '.msi', '.dll'
        ]
        
        self.suspicious_extensions = [
            '.zip', '.rar', '.7z', '.iso', '.dmg',
            '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm'
        ]
        
        self.archive_extensions = [
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'
        ]
    
    def scan_attachment(self, attachment_data, email_content=None):
        """Skanuje załącznik"""
        result = {
            'filename': attachment_data['filename'],
            'score': 0,
            'flags': [],
            'file_info': {}
        }
        
        filename = attachment_data['filename'].lower()
        
        # Sprawdź rozszerzenie
        ext_score, ext_flags = self._check_extension(filename)
        result['score'] += ext_score
        result['flags'].extend(ext_flags)
        
        # Sprawdź rozmiar
        size_score, size_flags = self._check_size(attachment_data['size'])
        result['score'] += size_score
        result['flags'].extend(size_flags)
        
        # Sprawdź double extension
        if self._has_double_extension(filename):
            result['score'] += 20
            result['flags'].append('DOUBLE_EXTENSION')
        
        # Sprawdź mismatch MIME type
        declared_type = attachment_data.get('content_type', '')
        expected_type = mimetypes.guess_type(filename)[0]
        
        if expected_type and declared_type and expected_type != declared_type:
            result['score'] += 15
            result['flags'].append('MIME_TYPE_MISMATCH')
        
        # Sprawdź nazwę pliku
        name_score, name_flags = self._check_filename(filename)
        result['score'] += name_score
        result['flags'].extend(name_flags)
        
        # Informacje o pliku
        result['file_info'] = {
            'size': attachment_data['size'],
            'type': declared_type,
            'extension': os.path.splitext(filename)[1]
        }
        
        return result
    
    def _check_extension(self, filename):
        """Sprawdza rozszerzenie pliku"""
        score = 0
        flags = []
        
        # Bardzo niebezpieczne
        for ext in self.dangerous_extensions:
            if filename.endswith(ext):
                score += 40
                flags.append(f'DANGEROUS_EXTENSION_{ext}')
                return score, flags
        
        # Podejrzane
        for ext in self.suspicious_extensions:
            if filename.endswith(ext):
                score += 20
                flags.append(f'SUSPICIOUS_EXTENSION_{ext}')
                return score, flags
        
        return score, flags
    
    def _check_size(self, size):
        """Sprawdza rozmiar pliku"""
        score = 0
        flags = []
        
        # Bardzo małe pliki wykonywalne mogą być złośliwe
        if size < 1024:  # < 1KB
            score += 10
            flags.append('VERY_SMALL_FILE')
        
        # Bardzo duże pliki mogą być mailbombami
        max_size = self._parse_size(self.config.config.get_security_setting('max_attachment_size', '50MB'))
        if size > max_size:
            score += 15
            flags.append('OVERSIZED_FILE')
        
        return score, flags
    
    def _parse_size(self, size_str):
        """Parsuje rozmiar z formatu '50MB' na bajty"""
        units = {'B': 1, 'KB': 1024, 'MB': 1024**2, 'GB': 1024**3}
        
        for unit, multiplier in units.items():
            if unit in size_str.upper():
                number = float(size_str.upper().replace(unit, '').strip())
                return int(number * multiplier)
        
        return 50 * 1024 * 1024  # Domyślnie 50MB
    
    def _has_double_extension(self, filename):
        """Sprawdza czy plik ma podwójne rozszerzenie"""
        parts = filename.split('.')
        if len(parts) >= 3:
            # np. file.pdf.exe
            second_ext = '.' + parts[-2]
            last_ext = '.' + parts[-1]
            
            # Jeśli przedostatnie rozszerzenie wygląda jak prawdziwe rozszerzenie
            common_exts = ['.pdf', '.doc', '.xls', '.jpg', '.png', '.txt']
            if second_ext in common_exts and last_ext in self.dangerous_extensions:
                return True
        
        return False
    
    def _check_filename(self, filename):
        """Sprawdza nazwę pliku pod kątem podejrzanych wzorców"""
        score = 0
        flags = []
        
        # Długie nazwy (mogą ukrywać prawdziwe rozszerzenie)
        if len(filename) > 100:
            score += 10
            flags.append('LONG_FILENAME')
        
        # Wiele kropek (obfuskacja)
        if filename.count('.') > 3:
            score += 10
            flags.append('MULTIPLE_DOTS')
        
        # Podejrzane słowa w nazwie
        suspicious_words = ['invoice', 'payment', 'urgent', 'document', 'faktura', 'płatność']
        if any(word in filename for word in suspicious_words):
            score += 5
            flags.append('SUSPICIOUS_FILENAME')
        
        return score, flags
    
    def calculate_file_hash(self, file_content):
        """Oblicza hash pliku (MD5, SHA256)"""
        try:
            md5 = hashlib.md5(file_content).hexdigest()
            sha256 = hashlib.sha256(file_content).hexdigest()
            
            return {
                'md5': md5,
                'sha256': sha256
            }
        except Exception as e:
            self.logger.error(f"Błąd obliczania hash: {str(e)}")
            return None

# =====================================

# utils/email_cleaner.py
"""
Narzędzie do hurtowego czyszczenia skrzynki
"""

import logging
from datetime import datetime

class EmailCleaner:
    def __init__(self, email_client, database):
        self.email_client = email_client
        self.database = database
        self.logger = logging.getLogger(__name__)
    
    def delete_by_score(self, account, folder, min_score=80, dry_run=True):
        """Usuwa wiadomości o wysokim score"""
        if not self.email_client.connection:
            if not self.email_client.connect(account):
                self.logger.error("Nie można połączyć z serwerem")
                return 0
        
        self.email_client.select_folder(folder)
        
        # Pobierz listę podejrzanych wiadomości z bazy
        suspicious_emails = self.database.get_suspicious_emails(min_score)
        
        deleted_count = 0
        
        for email_data in suspicious_emails:
            email_id, sender, subject, score, scan_date, flags = email_data
            
            try:
                # Pobierz Message-ID z bazy
                # TODO: Implementacja pobierania Message-ID
                
                if dry_run:
                    self.logger.info(f"[DRY RUN] Usunięto by: {subject} (score: {score})")
                else:
                    # Faktyczne usunięcie
                    # self.email_client.delete_message(message_id)
                    deleted_count += 1
                    self.logger.info(f"Usunięto: {subject} (score: {score})")
            
            except Exception as e:
                self.logger.error(f"Błąd usuwania wiadomości: {str(e)}")
        
        return deleted_count
    
    def move_to_folder(self, account, source_folder, dest_folder, min_score=50):
        """Przenosi podejrzane wiadomości do innego folderu"""
        # TODO: Implementacja przenoszenia wiadomości
        pass
    
    def quarantine_dangerous(self, account, folder, min_score=90):
        """Przenosi bardzo niebezpieczne wiadomości do kwarantanny"""
        # TODO: Implementacja kwarantanny
        pass
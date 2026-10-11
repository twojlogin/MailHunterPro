import re
import logging
import hashlib
import json
from urllib.parse import urlparse
import urllib.request
import urllib.error

class URLReputation:
    URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/url/'
    URLHAUS_HOST_API = 'https://urlhaus-api.abuse.ch/v1/host/'
    VT_API = 'https://www.virustotal.com/api/v3/urls'

    def __init__(self, vt_key=None, use_tor=False, socks_port=9050):
        self.vt_key = vt_key
        self.use_tor = use_tor
        self.socks_port = socks_port
        self.logger = logging.getLogger(__name__)

    def _get_urlopen(self):
        if self.use_tor:
            try:
                import socks
                import socket
                original_socket = socket.socket
                socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.socks_port)
                socket.socket = socks.socksocket
                return urllib.request.urlopen, original_socket
            except ImportError:
                self.logger.warning("PySocks not installed — Tor not available")
        return urllib.request.urlopen, None

    def _release_tor(self, original_socket):
        if original_socket:
            import socket
            socket.socket = original_socket

    def check_urlhaus(self, url):
        urlopen, original_socket = self._get_urlopen()
        try:
            data = f'url={url}'.encode()
            req = urllib.request.Request(self.URLHAUS_API, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            with urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
                if result.get('query_status') == 'url_found':
                    tags = result.get('tags', [])
                    url_status = result.get('url_status', '')
                    return {
                        'found': True,
                        'status': url_status,
                        'tags': tags,
                        'threat': result.get('threat', ''),
                        'source': 'URLhaus'
                    }
        except Exception as e:
            self.logger.warning(f'URLhaus lookup failed: {e}')
        finally:
            self._release_tor(original_socket)

        return {'found': False}

    def check_urlhaus_host(self, domain):
        urlopen, original_socket = self._get_urlopen()
        try:
            data = f'host={domain}'.encode()
            req = urllib.request.Request(self.URLHAUS_HOST_API, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            with urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
                if result.get('query_status') == 'no_results':
                    return {'found': False}
                urls_count = result.get('urls_online', 0)
                return {
                    'found': urls_count > 0,
                    'urls_online': urls_count,
                    'blacklists': result.get('blacklists', {}),
                    'source': 'URLhaus'
                }
        except Exception as e:
            self.logger.warning(f'URLhaus host lookup failed: {e}')
        finally:
            self._release_tor(original_socket)

        return {'found': False}

    def check_virustotal(self, url):
        if not self.vt_key:
            return None

        urlopen, original_socket = self._get_urlopen()
        try:
            url_id = hashlib.sha256(url.encode()).hexdigest()
            req = urllib.request.Request(f'{self.VT_API}/{url_id}')
            req.add_header('x-apikey', self.vt_key)
            with urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode())
                stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                return {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'harmless': stats.get('harmless', 0),
                    'total': sum(stats.values()) if stats else 0,
                    'source': 'VirusTotal'
                }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {'malicious': 0, 'suspicious': 0, 'total': 0, 'source': 'VirusTotal', 'note': 'Not found in VT'}
            self.logger.warning(f'VirusTotal lookup failed: {e}')
        except Exception as e:
            self.logger.warning(f'VirusTotal lookup failed: {e}')
        finally:
            self._release_tor(original_socket)

        return None

    def analyze_url(self, url):
        score = 0
        findings = []
        domain = urlparse(url).netloc

        if self._is_ip_url(url):
            score += 15
            findings.append({'type': 'IP_BASED_URL', 'weight': 15, 'detail': f'URL oparty na IP: {url}'})

        if self._is_shortener(url):
            score += 10
            findings.append({'type': 'URL_SHORTENER', 'weight': 10, 'detail': f'Skrócony link: {domain}'})

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.download', '.link', '.zip', '.mov']
        parsed = urlparse(url)
        for tld in suspicious_tlds:
            if parsed.netloc.endswith(tld):
                score += 15
                findings.append({'type': 'SUSPICIOUS_TLD', 'weight': 15, 'detail': f'Podejrzany TLD: {tld}'})
                break

        if '@' in parsed.netloc or '@' in url.split('://', 1)[-1]:
            score += 20
            findings.append({'type': 'URL_AT_SYMBOL', 'weight': 20, 'detail': 'URL zawiera @ — możliwy trick homograph'})

        path_lower = parsed.path.lower()
        phishing_paths = ['verify', 'secure', 'account', 'login', 'update', 'confirm', 'password', 'credential', 'banking', 'signin']
        if any(p in path_lower for p in phishing_paths):
            score += 10
            findings.append({'type': 'PHISHING_PATH_KEYWORD', 'weight': 10, 'detail': f'Podejrzane słowo w ścieżce URL'})

        redirect_params = ['url=', 'redirect=', 'next=', 'return=', 'go=', 'rurl=', 'dest=']
        if any(p in parsed.query.lower() for p in redirect_params):
            score += 15
            findings.append({'type': 'URL_REDIRECT', 'weight': 15, 'detail': 'URL zawiera parametr przekierowania'})

        urlhaus = self.check_urlhaus(url)
        if urlhaus.get('found'):
            score += 40
            findings.append({
                'type': 'URLHAUS_MALICIOUS',
                'weight': 40,
                'detail': f'URL na czarnej liście URLhaus. Status: {urlhaus.get("status")}, Tags: {urlhaus.get("tags")}'
            })

        vt_result = self.check_virustotal(url)
        if vt_result and vt_result.get('malicious', 0) > 0:
            score += 30
            findings.append({
                'type': 'VT_MALICIOUS',
                'weight': 30,
                'detail': f'VirusTotal: {vt_result["malicious"]} silników uznało za złośliwy'
            })

        return min(score, 100), findings

    def analyze_domain(self, domain):
        score = 0
        findings = []

        urlhaus = self.check_urlhaus_host(domain)
        if urlhaus.get('found'):
            score += 30
            findings.append({
                'type': 'DOMAIN_URLHAUS',
                'weight': 30,
                'detail': f'Domena na liście URLhaus. Online URLs: {urlhaus.get("urls_online", 0)}'
            })

        return min(score, 100), findings

    def _is_ip_url(self, url):
        match = re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url)
        return bool(match)

    def _is_shortener(self, url):
        shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'rebrand.ly', 'cutt.ly', 'bl.ink', 'lnkd.in',
            'rb.gy', 'shorturl.at', 'tiny.cc', 'clk.sh', 'cut.ly'
        ]
        domain = urlparse(url).netloc.lower()
        return any(s in domain for s in shorteners)

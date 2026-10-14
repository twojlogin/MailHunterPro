import re
import logging
import hashlib
import json
import time
from urllib.parse import urlparse
import urllib.request
import urllib.error
from functools import lru_cache


class URLReputation:
    URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/url/'
    URLHAUS_HOST_API = 'https://urlhaus-api.abuse.ch/v1/host/'
    VT_API = 'https://www.virustotal.com/api/v3/urls'

    def __init__(self, vt_key=None, use_tor=False, socks_port=9050, cache_ttl=300):
        self.vt_key = vt_key
        self.use_tor = use_tor
        self.socks_port = socks_port
        self.cache_ttl = cache_ttl
        self.logger = logging.getLogger(__name__)
        self._cache = {}

    def _cache_key(self, prefix, value):
        return f'{prefix}:{value}'

    def _get_cached(self, prefix, value):
        key = self._cache_key(prefix, value)
        entry = self._cache.get(key)
        if not entry:
            return None
        cached_at, result = entry
        if time.time() - cached_at > self.cache_ttl:
            self._cache.pop(key, None)
            return None
        return result

    def _set_cache(self, prefix, value, result):
        self._cache[self._cache_key(prefix, value)] = (time.time(), result)

    def _get_urlopen(self):
        if self.use_tor:
            try:
                import socks
                import socket
                original_socket = socket.socket
                socks.set_default_proxy(socks.SOCKS5, '127.0.0.1', self.socks_port)
                socket.socket = socks.socksocket
                return urllib.request.urlopen, original_socket
            except ImportError:
                self.logger.warning('PySocks not installed — Tor not available')
        return urllib.request.urlopen, None

    def _release_tor(self, original_socket):
        if original_socket:
            import socket
            socket.socket = original_socket

    def check_urlhaus(self, url):
        if not url or not isinstance(url, str):
            return {'found': False}

        cached = self._get_cached('urlhaus', url)
        if cached is not None:
            return cached

        urlopen, original_socket = self._get_urlopen()
        try:
            data = f'url={url}'.encode()
            req = urllib.request.Request(self.URLHAUS_API, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            with urlopen(req, timeout=10) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                result = json.loads(body or '{}')
                if result.get('query_status') == 'url_found':
                    response = {
                        'found': True,
                        'status': result.get('url_status', ''),
                        'tags': result.get('tags', []),
                        'threat': result.get('threat', ''),
                        'source': 'URLhaus'
                    }
                    self._set_cache('urlhaus', url, response)
                    return response
        except Exception as e:
            self.logger.warning(f'URLhaus lookup failed: {e}')
        finally:
            self._release_tor(original_socket)

        response = {'found': False}
        self._set_cache('urlhaus', url, response)
        return response

    def check_urlhaus_host(self, domain):
        if not domain or not isinstance(domain, str):
            return {'found': False}

        cached = self._get_cached('urlhaus_host', domain)
        if cached is not None:
            return cached

        urlopen, original_socket = self._get_urlopen()
        try:
            data = f'host={domain}'.encode()
            req = urllib.request.Request(self.URLHAUS_HOST_API, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            with urlopen(req, timeout=10) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                result = json.loads(body or '{}')
                if result.get('query_status') == 'no_results':
                    response = {'found': False}
                    self._set_cache('urlhaus_host', domain, response)
                    return response
                urls_count = result.get('urls_online', 0)
                response = {
                    'found': urls_count > 0,
                    'urls_online': urls_count,
                    'blacklists': result.get('blacklists', {}),
                    'source': 'URLhaus'
                }
                self._set_cache('urlhaus_host', domain, response)
                return response
        except Exception as e:
            self.logger.warning(f'URLhaus host lookup failed: {e}')
        finally:
            self._release_tor(original_socket)

        response = {'found': False}
        self._set_cache('urlhaus_host', domain, response)
        return response

    def check_virustotal(self, url):
        if not self.vt_key or not url or not isinstance(url, str):
            return None

        cached = self._get_cached('vt', url)
        if cached is not None:
            return cached

        urlopen, original_socket = self._get_urlopen()
        try:
            url_id = hashlib.sha256(url.encode()).hexdigest()
            req = urllib.request.Request(f'{self.VT_API}/{url_id}')
            req.add_header('x-apikey', self.vt_key)
            with urlopen(req, timeout=15) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                result = json.loads(body or '{}')
                stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                response = {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'harmless': stats.get('harmless', 0),
                    'total': sum(stats.values()) if stats else 0,
                    'source': 'VirusTotal'
                }
                self._set_cache('vt', url, response)
                return response
        except urllib.error.HTTPError as e:
            if e.code == 404:
                response = {'malicious': 0, 'suspicious': 0, 'total': 0, 'source': 'VirusTotal', 'note': 'Not found in VT'}
                self._set_cache('vt', url, response)
                return response
            self.logger.warning(f'VirusTotal lookup failed: {e}')
        except Exception as e:
            self.logger.warning(f'VirusTotal lookup failed: {e}')
        finally:
            self._release_tor(original_socket)

        return None

    def analyze_url(self, url):
        if not url or not isinstance(url, str):
            return 0, []

        score = 0
        findings = []
        try:
            parsed = urlparse(url)
            domain = parsed.netloc

            if self._is_ip_url(url):
                score += 15
                findings.append({'type': 'IP_BASED_URL', 'weight': 15, 'detail': f'URL oparty na IP: {url}'})

            if self._is_shortener(url):
                score += 10
                findings.append({'type': 'URL_SHORTENER', 'weight': 10, 'detail': f'Skrócony link: {domain}'})

            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.download', '.link', '.zip', '.mov']
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
                findings.append({'type': 'PHISHING_PATH_KEYWORD', 'weight': 10, 'detail': 'Podejrzane słowo w ścieżce URL'})

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
        except Exception as e:
            self.logger.warning(f'analyze_url failed for {url}: {e}')
            return 0, []

    def analyze_domain(self, domain):
        if not domain or not isinstance(domain, str):
            return 0, []

        score = 0
        findings = []
        try:
            urlhaus = self.check_urlhaus_host(domain)
            if urlhaus.get('found'):
                score += 30
                findings.append({
                    'type': 'DOMAIN_URLHAUS',
                    'weight': 30,
                    'detail': f'Domena na liście URLhaus. Online URLs: {urlhaus.get("urls_online", 0)}'
                })

            return min(score, 100), findings
        except Exception as e:
            self.logger.warning(f'analyze_domain failed for {domain}: {e}')
            return 0, []

    def _is_ip_url(self, url):
        try:
            return bool(re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url or ''))
        except Exception:
            return False

    def _is_shortener(self, url):
        try:
            shorteners = [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
                'buff.ly', 'rebrand.ly', 'cutt.ly', 'bl.ink', 'lnkd.in',
                'rb.gy', 'shorturl.at', 'tiny.cc', 'clk.sh', 'cut.ly'
            ]
            domain = urlparse(url or '').netloc.lower()
            return any(s in domain for s in shorteners)
        except Exception:
            return False

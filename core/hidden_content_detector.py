import re
import logging
from bs4 import BeautifulSoup

class HiddenContentDetector:
    DEVICE_ACCESS_PATTERNS = [
        # Camera/Microphone access via HTML5
        r'getUserMedia',
        r'mediaDevices',
        r'navigator\.media',
        r'(?:video|audio)\s*(?:input|stream)',
        r'(?:camera|microphone|webcam|mic)',
        # WebRTC
        r'RTCPeerConnection',
        r'RTCDataChannel',
        r'RTCSessionDescription',
        # Geolocation
        r'geolocation',
        r'getCurrentPosition',
        r'watchPosition',
        # Device sensors
        r'DeviceOrientationEvent',
        r'DeviceMotionEvent',
        r'Accelerometer',
        r'Gyroscope',
        r'Magnetometer',
        # Notifications
        r'Notification\.requestPermission',
        r'pushManager',
        # Fullscreen
        r'requestFullscreen',
        r'mozRequestFullScreen',
        r'webkitRequestFullscreen',
        # Clipboard
        r'readText',
        r'writeText',
        r'clipboardData',
        # FileSystem
        r'requestFileSystem',
        r'webkitRequestFileSystem',
    ]

    MALICIOUS_JS_PATTERNS = [
        # Data exfiltration
        r'fetch\s*\(\s*["\'][^"\']*(?:collect|send|report|log|track|beacon|pixel)[^"\']*["\']',
        r'XMLHttpRequest[^}]*\.open\s*\(\s*["\']POST',
        r'new\s+Image\s*\(\s*\)\s*\.src\s*=',
        r'navigator\.sendBeacon',
        r'window\.onerror\s*=',
        r'document\.write\s*\(\s*unescape',
        r'eval\s*\(\s*(?:document|window|location)',
        r'String\.fromCharCode\s*\(',
        r'atob\s*\(',
        # Keylogger patterns
        r'addEventListener\s*\(\s*["\'](?:keydown|keyup|keypress)',
        r'onkey(?:down|up|press)',
        r'(?:get|capture)Key(?:board|Stroke)',
        # Cookie theft
        r'document\.cookie',
        r'(?:steal|exfil|grab|harvest)\s*(?:cookie|session|token)',
        # Form hijacking
        r'(?:password|email|login|credential|credit.?card|bank)',
        # Browser fingerprinting
        r'canvas\.toDataURL',
        r'fingerprint',
        r'WebGLRenderingContext',
        r'(?:screen\.width|screen\.height|navigator\.platform)',
        # Clipboard hijacking
        r'(?:oncopy|oncut|onpaste)',
        r'clipboard\s*=\s*',
    ]

    HIDDEN_ELEMENTS = [
        # CSS hiding techniques
        (r'position\s*:\s*absolute[^;]*(?:left|top)\s*:\s*-\d{3,}', 'Off-screen positioning'),
        (r'clip\s*:\s*rect\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)', 'CSS clip hidden'),
        (r'overflow\s*:\s*hidden[^;]*height\s*:\s*0', 'Collapsed hidden element'),
        (r'opacity\s*:\s*0[^;]*(?:position|z-index)', 'Invisible but interactive'),
        (r'z-index\s*:\s*-\d+', 'Behind other elements'),
        (r'pointer-events\s*:\s*none[^;]*visibility\s*:\s*visible', 'Visible but non-interactive overlay'),
    ]

    HIDDEN_IFRAME_PATTERNS = [
        r'<iframe[^>]+style=["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)',
        r'<iframe[^>]+width=["\']?0["\']?',
        r'<iframe[^>]+height=["\']?0["\']?',
        r'<iframe[^>]+src=["\']?javascript:',
    ]

    SUSPICIOUS_FORM_ACTIONS = [
        r'action\s*=\s*["\'][^"\']*(?:collect|steal|harvest|exfil|send|track)',
        r'method\s*=\s*["\']?post["\']?[^>]*action\s*=\s*["\']?(?!https?://(?:www\.)?(?:google|github|microsoft|apple))',
    ]

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze(self, parsed_email):
        score = 0
        findings = []

        body_html = parsed_email.get('body', {}).get('html', '')
        body_text = parsed_email.get('body', {}).get('text', '')
        content = body_text + ' ' + body_html

        device_score, device_findings = self._check_device_access(content)
        score += device_score
        findings.extend(device_findings)

        js_score, js_findings = self._check_malicious_js(body_html)
        score += js_score
        findings.extend(js_findings)

        hidden_score, hidden_findings = self._check_hidden_elements(body_html)
        score += hidden_score
        findings.extend(hidden_findings)

        iframe_score, iframe_findings = self._check_hidden_iframes(body_html)
        score += iframe_score
        findings.extend(iframe_findings)

        form_score, form_findings = self._check_suspicious_forms(body_html)
        score += form_score
        findings.extend(form_findings)

        return min(score, 100), findings

    def _check_device_access(self, content):
        score = 0
        findings = []

        for pattern in self.DEVICE_ACCESS_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                keyword = match.group()
                kw_lower = keyword.lower()
                context = content[max(0, match.start()-50):match.end()+50].lower()
                if any(cam in kw_lower for cam in ['camera', 'webcam']) or ('getusermedia' in kw_lower and 'audio' not in context):
                    score += 30
                    findings.append({
                        'type': 'CAMERA_ACCESS',
                        'weight': 30,
                        'detail': f'Próba dostępu do kamery: "{keyword}"'
                    })
                if any(mic in kw_lower for mic in ['microphone', 'mic', 'audio']) or ('getusermedia' in kw_lower and 'audio' in context):
                    score += 30
                    findings.append({
                        'type': 'MICROPHONE_ACCESS',
                        'weight': 30,
                        'detail': f'Próba dostępu do mikrofonu: "{keyword}"'
                    })
                if 'getusermedia' in kw_lower and 'audio' not in context and not any(cam in kw_lower for cam in ['camera', 'webcam']):
                    score += 30
                    findings.append({
                        'type': 'CAMERA_ACCESS',
                        'weight': 30,
                        'detail': f'Próba dostępu do kamery/mikrofonu: "{keyword}"'
                    })
                elif any(loc in keyword.lower() for loc in ['geolocation', 'getcurrentposition']):
                    score += 20
                    findings.append({
                        'type': 'LOCATION_ACCESS',
                        'weight': 20,
                        'detail': f'Próba dostępu do lokalizacji: "{keyword}"'
                    })
                elif any(sensor in keyword.lower() for sensor in ['deviceorientation', 'devicemotion', 'accelerometer', 'gyroscope']):
                    score += 20
                    findings.append({
                        'type': 'SENSOR_ACCESS',
                        'weight': 20,
                        'detail': f'Próba dostępu do sensorów: "{keyword}"'
                    })
                elif any(clip in keyword.lower() for clip in ['clipboard', 'readtext', 'writetext']):
                    score += 15
                    findings.append({
                        'type': 'CLIPBOARD_ACCESS',
                        'weight': 15,
                        'detail': f'Próba dostępu do schowka: "{keyword}"'
                    })
                elif any(notif in keyword.lower() for notif in ['notification', 'pushmanager']):
                    score += 10
                    findings.append({
                        'type': 'NOTIFICATION_ACCESS',
                        'weight': 10,
                        'detail': f'Próba dostępu do powiadomień: "{keyword}"'
                    })
                elif any(fs in keyword.lower() for fs in ['fullscreen']):
                    score += 5
                    findings.append({
                        'type': 'FULLSCREEN_REQUEST',
                        'weight': 5,
                        'detail': f'Żądanie pełnego ekranu: "{keyword}"'
                    })

        return score, findings

    def _check_malicious_js(self, html):
        score = 0
        findings = []

        if not html:
            return score, findings

        soup = BeautifulSoup(html, 'html.parser')

        for script in soup.find_all('script'):
            script_content = script.string or ''
            src = script.get('src', '')

            if src and src.startswith('http'):
                for pattern in self.MALICIOUS_JS_PATTERNS:
                    if re.search(pattern, src, re.IGNORECASE):
                        score += 20
                        findings.append({
                            'type': 'MALICIOUS_SCRIPT_SRC',
                            'weight': 20,
                            'detail': f'Podejrzany external script: {src[:80]}'
                        })
                        break

            for pattern in self.MALICIOUS_JS_PATTERNS:
                match = re.search(pattern, script_content, re.IGNORECASE)
                if match:
                    keyword = match.group()
                    if any(k in keyword.lower() for k in ['fetch', 'sendbeacon', 'xmlhttprequest', 'new image']):
                        score += 20
                        findings.append({
                            'type': 'DATA_EXFILTRATION',
                            'weight': 20,
                            'detail': f'Egzfiltracja danych: "{keyword[:40]}"'
                        })
                    elif any(k in keyword.lower() for k in ['keydown', 'keyup', 'keypress', 'onkey']):
                        score += 25
                        findings.append({
                            'type': 'KEYLOGGER',
                            'weight': 25,
                            'detail': f'Wykryto keylogger: "{keyword[:40]}"'
                        })
                    elif 'cookie' in keyword.lower():
                        score += 20
                        findings.append({
                            'type': 'COOKIE_THEFT',
                            'weight': 20,
                            'detail': f'Próba kradzieży ciasteczek: "{keyword[:40]}"'
                        })
                    elif 'fingerprint' in keyword.lower():
                        score += 15
                        findings.append({
                            'type': 'BROWSER_FINGERPRINTING',
                            'weight': 15,
                            'detail': f'Browser fingerprinting: "{keyword[:40]}"'
                        })
                    elif 'eval' in keyword.lower() or 'fromcharcode' in keyword.lower():
                        score += 25
                        findings.append({
                            'type': 'EVAL_OBFUSCATION',
                            'weight': 25,
                            'detail': f'Obfuskacja JS (eval/fromCharCode): "{keyword[:40]}"'
                        })
                    elif 'clipboard' in keyword.lower():
                        score += 15
                        findings.append({
                            'type': 'CLIPBOARD_HIJACK',
                            'weight': 15,
                            'detail': f'Przejęcie schowka: "{keyword[:40]}"'
                        })
                    break

        return score, findings

    def _check_hidden_elements(self, html):
        score = 0
        findings = []

        if not html:
            return score, findings

        for pattern, desc in self.HIDDEN_ELEMENTS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                score += 15
                findings.append({
                    'type': 'HIDDEN_ELEMENT',
                    'weight': 15,
                    'detail': f'Ukryty element HTML: {desc} ({len(matches)} wystąpień)'
                })

        soup = BeautifulSoup(html, 'html.parser')

        for element in soup.find_all(True):
            style = element.get('style', '').lower()
            classes = ' '.join(element.get('class', []))
            element_str = str(element)[:200]

            if 'display:none' in style.replace(' ', '') or 'display: none' in style:
                if element.name in ['div', 'span', 'p', 'a', 'input', 'form', 'button']:
                    text = element.get_text(strip=True)
                    if text or element.name in ['input', 'form']:
                        score += 15
                        findings.append({
                            'type': 'HIDDEN_INTERACTIVE',
                            'weight': 15,
                            'detail': f'Ukryty element interaktywny <{element.name}>: "{text[:40]}"'
                        })

        return score, findings

    def _check_hidden_iframes(self, html):
        score = 0
        findings = []

        if not html:
            return score, findings

        for pattern in self.HIDDEN_IFRAME_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                score += 25
                findings.append({
                    'type': 'HIDDEN_IFRAME',
                    'weight': 25,
                    'detail': f'Ukryty iframe ({len(matches)} znalezionych) — możliwy drive-by download'
                })

        return score, findings

    def _check_suspicious_forms(self, html):
        score = 0
        findings = []

        if not html:
            return score, findings

        for pattern in self.SUSPICIOUS_FORM_ACTIONS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                score += 20
                findings.append({
                    'type': 'SUSPICIOUS_FORM',
                    'weight': 20,
                    'detail': f'Podejrzany formularz: {matches[0][:60]}'
                })

        soup = BeautifulSoup(html, 'html.parser')

        for form in soup.find_all('form'):
            action = form.get('action', '')
            inputs = form.find_all('input')
            input_names = [inp.get('name', '').lower() for inp in inputs]

            sensitive_fields = ['password', 'credit', 'card', 'ssn', 'social', 'bank', 'account', 'login', 'credential']
            has_sensitive = any(any(s in name for s in sensitive_fields) for name in input_names)

            if has_sensitive and action and not action.startswith('#'):
                parsed_action = action.lower()
                if not any(trusted in parsed_action for trusted in ['google', 'microsoft', 'apple', 'github', 'amazon']):
                    score += 20
                    findings.append({
                        'type': 'PHISHING_FORM',
                        'weight': 20,
                        'detail': f'Formularz phishingowy (pola: {", ".join(input_names[:3])}), action: {action[:60]}'
                    })

        return score, findings

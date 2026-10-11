import re
import logging
import base64
import quopri
from bs4 import BeautifulSoup

class PromptDetector:
    SYSTEM_PROMPT_PATTERNS = [
        # English
        r'ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules|directives)',
        r'disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|context)',
        r'you\s+are\s+now\s+(?:a|an)\s+',
        r'act\s+as\s+(?:a|an)\s+',
        r'pretend\s+(?:you\s+are|to\s+be)\s+',
        r'roleplay\s+as\s+',
        r'from\s+now\s+on\s+(?:you\s+)?(?:will|must|should|shall)',
        r'new\s+instructions?\s*:',
        r'system\s*prompt\s*:',
        r'system\s*message\s*:',
        r'override\s+(?:all\s+)?(?:previous|prior|safety)',
        r'bypass\s+(?:all\s+)?(?:safety|content|security)',
        r'you\s+(?:must|should|will)\s+(?:now\s+)?(?:ignore|disregard|override)',
        r'(?:do|please)\s+not\s+(?:follow|obey|adhere\s+to)\s+(?:your|the)\s+(?:previous|prior|existing)',
        r'(?:forget|erase|delete)\s+(?:everything|all|your)\s+(?:you|have|know)',
        r'(?:output|print|reveal|show)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|rules)',
        r'(?:what|repeat)\s+(?:is\s+)?your\s+(?:system\s+)?(?:prompt|instructions?)',
        r'(?:hidden|secret)\s+(?:instructions?|prompt|mode)',
        r'(?:developer|admin|root)\s+mode',
        r'(?:jailbreak|DAN|do\s+anything\s+now)',

        # Polish
        r'ignoruj\s+(?:wszystkie\s+)?(?:poprzednie|powyższe)\s+(?:instrukcje|polecenia|reguły)',
        r'zignoruj\s+(?:wszystkie\s+)?(?:poprzednie|wcześniejsze)\s+(?:instrukcje|polecenia)',
        r'od\s+teraz\s+(?:będziesz|musisz|powinieneś)',
        r'nowe\s+instrukcje\s*:',
        r'zadanie\s*:',
        r'jesteś\s+teraz\s+',
        r'udajesz\s+že\s+',
        r'zachowuj\s+się\s+jak\s+',
        r'podaj\s+(?:swój|swoje|swoich)\s+(?:prompt|instrukcje|reguły)',
        r'co\s+(?:jest|masz)\s+w\s+(?:swoim|swoich)\s+(?:prompt|instrukcjach)',
        r'pomiń\s+(?:wszystkie\s+)?(?:zabezpieczenia|ograniczenia|reguły)',
        r'przełam\s+(?:wszystkie\s+)?(?:zabezpieczenia|blokady)',
        r'włącz\s+tryb\s+(?:deweloperski|administratora|root)',
        r'tryb\s+(?:deweloperski|administratora|root)\s*:',
    ]

    # Prompt injection obfuscation patterns
    OBFUSCATION_PATTERNS = [
        # Unicode homoglyphs
        (r'[аеорсухАЕОРСХ]', 'Cyrillic homoglyphs in ASCII context'),
        # Zero-width characters
        (r'[\u200b\u200c\u200d\ufeff]', 'Zero-width characters'),
        # RTL/LTR override
        (r'[\u202a-\u202e\u2066-\u2069]', 'Bidirectional override'),
        # Invisible separators
        (r'[\u2060\u2061\u2062\u2063\u2064]', 'Invisible separators'),
        # Homoglyph confusables (careful - only in suspicious context)
        (r'[а-яА-ЯёЁ]{3,}', 'Cyrillic characters in non-Cyrillic text'),
    ]

    SENSITIVE_DATA_REQUESTS = [
        r'(?:send|email|forward|cc|bcc)\s+(?:me\s+)?(?:all\s+)?(?:your|the|my)\s+(?:password|credentials|tokens?|keys?|api[_\s]?key)',
        r'(?:what|where)\s+is\s+(?:your|the)\s+(?:api[_\s]?key|token|secret|password)',
        r'(?:enter|input|provide|type)\s+(?:your|the)\s+(?:password|credentials|api[_\s]?key)',
        r'(?:login|sign\s?in|log\s?in)\s+(?:here|now|at|to)',
        r'(?:verify|confirm|validate)\s+(?:your|the)\s+(?:account|identity|email)',
        r'(?:update|confirm|verify)\s+(?:your|the)\s+(?:payment|billing|credit\s+card)',
        r'(?:suspended|limited|locked|blocked)\s+(?:account|access)',
        r'(?:click|tap)\s+(?:here|this|below)\s+(?:to\s+)?(?:verify|confirm|restore|unlock)',
        r'(?:within|in)\s+\d+\s+hours?\s+(?:or|before)\s+(?:your|the)\s+(?:account|access)',
    ]

    HIDDEN_INSTRUCTION_VECTORS = [
        # Hidden in HTML comments
        (r'<!--[\s\S]*?(?:ignore|override|system|prompt|instruction)[\s\S]*?-->', 'Hidden instruction in HTML comment'),
        # Hidden in CSS
        (r'/\*[\s\S]*?(?:ignore|override|system|prompt|instruction)[\s\S]*?\*/', 'Hidden instruction in CSS'),
        # Hidden in data attributes
        (r'data-(?:prompt|instruction|system|override)\s*=\s*["\'][^"\']+', 'Hidden instruction in data attribute'),
        # Hidden in zero-font text
        (r'font-size\s*:\s*0[^;]*;[^"]*(?:ignore|override|system|prompt)', 'Zero-font hidden text'),
        # Hidden in alt/title attributes
        r'alt\s*=\s*["\'][^"\']*(?:ignore|override|system|prompt)[^"\']*["\']',
        # Hidden in SVG
        r'<svg[^>]*>[\s\S]*?(?:ignore|override|system|prompt)[\s\S]*?</svg>',
        # Hidden in base64 encoded content in HTML
        r'src\s*=\s*["\']data:text/html;base64,[^"\']*(?:ignore|override|system|prompt)',
    ]

    AI_PLATFORM_KEYWORDS = [
        'openai', 'chatgpt', 'gpt-4', 'gpt-3', 'claude', 'anthropic',
        'bard', 'gemini', 'copilot', 'midjourney', 'dall-e',
        'stable diffusion', 'llama', 'mistral', 'palm',
    ]

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze(self, parsed_email):
        score = 0
        findings = []

        body_text = parsed_email.get('body', {}).get('text', '')
        body_html = parsed_email.get('body', {}).get('html', '')
        headers = parsed_email.get('headers', {})

        text_score, text_findings = self._check_text_content(body_text)
        score += text_score
        findings.extend(text_findings)

        html_score, html_findings = self._check_html_content(body_html)
        score += html_score
        findings.extend(html_findings)

        encoded_score, encoded_findings = self._check_encoded_content(body_text, body_html)
        score += encoded_score
        findings.extend(encoded_findings)

        obfuscation_score, obfuscation_findings = self._check_obfuscation(body_text, body_html)
        score += obfuscation_score
        findings.extend(obfuscation_findings)

        social_score, social_findings = self._check_social_engineering(body_text + ' ' + body_html)
        score += social_score
        findings.extend(social_findings)

        ai_score, ai_findings = self._check_ai_platform_references(body_text + ' ' + body_html)
        score += ai_score
        findings.extend(ai_findings)

        return min(score, 100), findings

    def _check_text_content(self, text):
        score = 0
        findings = []

        if not text:
            return score, findings

        text_lower = text.lower()

        for pattern in self.SYSTEM_PROMPT_PATTERNS:
            match = re.search(pattern, text_lower, re.IGNORECASE)
            if match:
                score += 30
                findings.append({
                    'type': 'SYSTEM_PROMPT_INJECTION',
                    'weight': 30,
                    'detail': f'Wykryto próbę wstrzyknięcia promptu systemowego: "{match.group()[:60]}"'
                })

        for pattern in self.SENSITIVE_DATA_REQUESTS:
            match = re.search(pattern, text_lower, re.IGNORECASE)
            if match:
                score += 20
                findings.append({
                    'type': 'SENSITIVE_DATA_REQUEST',
                    'weight': 20,
                    'detail': f'Żądanie wrażliwych danych: "{match.group()[:60]}"'
                })

        return score, findings

    def _check_html_content(self, html):
        score = 0
        findings = []

        if not html:
            return score, findings

        for pattern in self.HIDDEN_INSTRUCTION_VECTORS:
            if isinstance(pattern, tuple):
                regex, desc = pattern
            else:
                regex, desc = pattern, 'Hidden instruction vector'

            matches = re.findall(regex, html, re.IGNORECASE | re.DOTALL)
            if matches:
                score += 25
                findings.append({
                    'type': 'HIDDEN_INSTRUCTION',
                    'weight': 25,
                    'detail': f'{desc}: znaleziono {len(matches)} wystąpień'
                })

        soup = BeautifulSoup(html, 'html.parser')

        for element in soup.find_all(style=True):
            style = element.get('style', '').lower()
            if any(x in style for x in ['font-size:0', 'font-size: 0', 'visibility:hidden', 'visibility: hidden', 'opacity:0', 'opacity: 0', 'height:0', 'height: 0', 'width:0', 'width: 0']):
                text = element.get_text(strip=True)
                if text and len(text) > 5:
                    score += 20
                    findings.append({
                        'type': 'HIDDEN_VISIBLE_TEXT',
                        'weight': 20,
                        'detail': f'Ukryty tekst w HTML (niewidoczny wizualnie): "{text[:50]}"'
                    })

        for noscript in soup.find_all('noscript'):
            text = noscript.get_text(strip=True)
            if text and any(kw in text.lower() for kw in ['ignore', 'override', 'system', 'prompt', 'instruction']):
                score += 15
                findings.append({
                    'type': 'NOSCRIPT_INSTRUCTION',
                    'weight': 15,
                    'detail': f'Podejrzana treść w <noscript>: "{text[:50]}"'
                })

        return score, findings

    def _check_encoded_content(self, text, html):
        score = 0
        findings = []
        content = text + ' ' + html

        base64_pattern = r'(?:base64|b64)[,\s:=]+([A-Za-z0-9+/]{20,}={0,2})'
        for match in re.finditer(base64_pattern, content, re.IGNORECASE):
            encoded = match.group(1)
            try:
                decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                decoded_lower = decoded.lower()
                if any(kw in decoded_lower for kw in ['ignore', 'override', 'system', 'prompt', 'instruction', 'password', 'token']):
                    score += 30
                    findings.append({
                        'type': 'ENCODED_INSTRUCTION',
                        'weight': 30,
                        'detail': f'Zakodowana wiadomość (base64) zawiera podejrzane słowa kluczowe'
                    })
            except:
                pass

        quoted_printable_pattern = r'=\?[^\?]+\?Q\?([^\?]+)\?='
        for match in re.finditer(quoted_printable_pattern, content):
            try:
                decoded = quopri.decodestring(match.group(1).encode()).decode('utf-8', errors='ignore')
                if any(kw in decoded.lower() for kw in ['ignore', 'override', 'system', 'prompt']):
                    score += 25
                    findings.append({
                        'type': 'QP_ENCODED_INSTRUCTION',
                        'weight': 25,
                        'detail': 'Zakodowana wiadomość (Quoted-Printable) zawiera podejrzane instrukcje'
                    })
            except:
                pass

        return score, findings

    def _check_obfuscation(self, text, html):
        score = 0
        findings = []
        content = text + ' ' + html

        for pattern, desc in self.OBFUSCATION_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                if 'Cyrillic' in desc:
                    ascii_chars = re.findall(r'[a-zA-Z]', content)
                    if len(ascii_chars) > 20:
                        score += 15
                        findings.append({
                            'type': 'HOMOGLYPH_ATTACK',
                            'weight': 15,
                            'detail': f'{desc}: znaleziono {len(matches)} podejrzanych znaków'
                        })
                else:
                    score += 20
                    findings.append({
                        'type': 'OBFUSCATION',
                        'weight': 20,
                        'detail': f'{desc}: znaleziono {len(matches)} wystąpień'
                    })

        return score, findings

    def _check_social_engineering(self, content):
        score = 0
        findings = []
        content_lower = content.lower()

        urgency_patterns = [
            r'(?:act|respond|reply)\s+now\s+or',
            r'(?:within|in)\s+\d+\s+(?:minutes?|hours?|days?)\s+or',
            r'(?:final|last)\s+(?:notice|warning|chance)',
            r'(?:your|the)\s+(?:account|access)\s+will\s+be\s+(?:deleted|terminated|suspended|locked)',
            r'(?:immediate(?:ly)?|urgent|critical)\s+(?:action|response|required)',
            r'(?:failure|not)\s+(?:to\s+)?(?:act|respond|comply)\s+(?:will|may|might|could)\s+(?:result|lead)',
        ]

        for pattern in urgency_patterns:
            match = re.search(pattern, content_lower)
            if match:
                score += 10
                findings.append({
                    'type': 'URGENCY_LANGUAGE',
                    'weight': 10,
                    'detail': f'Język pilności/strachu: "{match.group()[:50]}"'
                })
                break

        authority_patterns = [
            r'(?:this\s+is\s+)?(?:a\s+)?(?:legal|official|government|irs|fbi|police|court)\s+(?:notice|warning|order|demand)',
            r'(?:failure\s+to\s+comply)\s+(?:will\s+)?(?:result|may\s+result|could\s+result)\s+in\s+(?:legal|criminal|civil)',
            r'(?:your\s+)?(?:social\s+security|national\s+insurance|pesel)\s+(?:number|will\s+be)',
        ]

        for pattern in authority_patterns:
            match = re.search(pattern, content_lower)
            if match:
                score += 15
                findings.append({
                    'type': 'FAKE_AUTHORITY',
                    'weight': 15,
                    'detail': f'Fałszywy autorytet: "{match.group()[:50]}"'
                })
                break

        return score, findings

    def _check_ai_platform_references(self, content):
        score = 0
        findings = []
        content_lower = content.lower()

        for platform in self.AI_PLATFORM_KEYWORDS:
            if platform in content_lower:
                context_patterns = [
                    rf'{platform}[^"]*(?:ignore|override|bypass|jailbreak)',
                    rf'(?:ignore|override|bypass|jailbreak)[^"]*{platform}',
                    rf'(?:your|the)\s+{platform}\s+(?:instructions?|rules?|prompts?)',
                    rf'{platform}\s+(?:mode|admin|developer|debug)',
                ]
                for pattern in context_patterns:
                    match = re.search(pattern, content_lower)
                    if match:
                        score += 20
                        findings.append({
                            'type': 'AI_PLATFORM_ABUSE',
                            'weight': 20,
                            'detail': f'Podejrzane odniesienie do {platform}: "{match.group()[:50]}"'
                        })
                        break

        return score, findings

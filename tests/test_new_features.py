import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.header_analyzer import HeaderAnalyzer
from core.ioc_extractor import IOCExtractor
from core.brand_detector import BrandDetector
from core.url_reputation import URLReputation

class TestHeaderAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = HeaderAnalyzer()

    def test_spf_pass(self):
        headers = {'Authentication-Results': 'mx.google.com; spf=pass'}
        score, findings = self.analyzer._check_spf(headers)
        self.assertEqual(score, 0)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'SPF_PASS')

    def test_spf_fail(self):
        headers = {'Authentication-Results': 'mx.google.com; spf=fail'}
        score, findings = self.analyzer._check_spf(headers)
        self.assertEqual(score, 20)
        self.assertEqual(findings[0]['type'], 'SPF_FAIL')

    def test_spf_softfail(self):
        headers = {'Authentication-Results': 'mx.google.com; spf=softfail'}
        score, findings = self.analyzer._check_spf(headers)
        self.assertEqual(score, 10)

    def test_spf_missing(self):
        headers = {}
        score, findings = self.analyzer._check_spf(headers)
        self.assertEqual(score, 15)
        self.assertEqual(findings[0]['type'], 'SPF_MISSING')

    def test_dkim_pass(self):
        headers = {'Authentication-Results': 'mx.google.com; dkim=pass'}
        score, findings = self.analyzer._check_dkim(headers)
        self.assertEqual(score, 0)

    def test_dkim_fail(self):
        headers = {'Authentication-Results': 'mx.google.com; dkim=fail'}
        score, findings = self.analyzer._check_dkim(headers)
        self.assertEqual(score, 15)

    def test_dmarc_pass(self):
        headers = {'Authentication-Results': 'mx.google.com; dmarc=pass'}
        score, findings = self.analyzer._check_dmarc(headers)
        self.assertEqual(score, 0)

    def test_dmarc_fail(self):
        headers = {'Authentication-Results': 'mx.google.com; dmarc=fail'}
        score, findings = self.analyzer._check_dmarc(headers)
        self.assertEqual(score, 20)

    def test_from_returnpath_mismatch(self):
        headers = {
            'From': 'user@example.com',
            'Return-Path': '<attacker@evil.com>'
        }
        score, findings = self.analyzer._check_sender(headers)
        self.assertGreater(score, 0)
        types = [f['type'] for f in findings]
        self.assertIn('FROM_RETURNPATH_MISMATCH', types)

    def test_brand_impersonation_in_display_name(self):
        headers = {
            'From': '"Microsoft Security" <phishing@malicious-domain.xyz>'
        }
        score, findings = self.analyzer._check_sender(headers)
        self.assertGreater(score, 0)
        types = [f['type'] for f in findings]
        self.assertIn('BRAND_IMPERSONATION', types)

    def test_full_analysis(self):
        headers = {
            'From': 'user@example.com',
            'Return-Path': '<user@example.com>',
            'Authentication-Results': 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'
        }
        score, findings = self.analyzer.analyze(headers)
        self.assertEqual(score, 0)


class TestIOCExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = IOCExtractor()

    def test_extract_urls(self):
        content = 'Visit https://example.com and http://test.org/path?q=1'
        urls = self.extractor._extract_urls(content, {})
        self.assertEqual(len(urls), 2)

    def test_extract_ips(self):
        content = 'Server at 8.8.8.8 and 1.1.1.1 responded'
        ips = self.extractor._extract_ips(content, {})
        self.assertEqual(len(ips), 2)

    def test_private_ip_filtered(self):
        content = 'Local: 192.168.1.1 and public 8.8.8.8'
        ips = self.extractor._extract_ips(content, {})
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0], '8.8.8.8')

    def test_extract_emails(self):
        content = 'Contact admin@example.com or support@test.org'
        emails = self.extractor._extract_emails(content)
        self.assertEqual(len(emails), 2)

    def test_extract_hashes(self):
        content = 'MD5: d41d8cd98f00b204e9800998ecf8427e'
        hashes = self.extractor._extract_hashes(content)
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0]['type'], 'MD5')

    def test_defang_url(self):
        iocs = {'urls': ['https://evil.com/path'], 'ips': [], 'domains': [], 'emails': []}
        defanged = self.extractor._defang_all(iocs)
        self.assertEqual(len(defanged), 1)
        self.assertIn('[.]', defanged[0]['defanged'])

    def test_full_extract(self):
        parsed = {
            'body': {'text': 'Click https://phish.com and send to user@test.com', 'html': ''},
            'headers': {'Received_IPs': ['1.2.3.4']},
            'attachments': []
        }
        iocs = self.extractor.extract_all(parsed)
        self.assertIn('urls', iocs)
        self.assertIn('emails', iocs)


class TestBrandDetector(unittest.TestCase):
    def setUp(self):
        self.detector = BrandDetector()

    def test_microsoft_display_impersonation(self):
        parsed = {
            'headers': {'From': '"Microsoft Account" <phishing@malicious.xyz>'},
            'body': {'text': '', 'html': ''}
        }
        score, findings = self.detector.analyze(parsed)
        self.assertGreater(score, 0)
        brands = [f['brand'] for f in findings]
        self.assertIn('microsoft', brands)

    def test_google_trusted_no_flag(self):
        parsed = {
            'headers': {'From': '"Google" <no-reply@google.com>'},
            'body': {'text': '', 'html': ''}
        }
        score, findings = self.detector.analyze(parsed)
        self.assertEqual(score, 0)

    def test_paypal_brand_in_body(self):
        parsed = {
            'headers': {'From': 'user@random-domain.com'},
            'body': {'text': 'Your PayPal account has been limited', 'html': ''}
        }
        score, findings = self.detector.analyze(parsed)
        self.assertGreater(score, 0)

    def test_no_brand(self):
        parsed = {
            'headers': {'From': 'friend@gmail.com'},
            'body': {'text': 'Hey, lets meet tomorrow', 'html': ''}
        }
        score, findings = self.detector.analyze(parsed)
        self.assertEqual(score, 0)


class TestURLReputation(unittest.TestCase):
    def setUp(self):
        self.reputation = URLReputation()

    def test_ip_url_detection(self):
        score, findings = self.reputation.analyze_url('http://192.168.1.1/login')
        types = [f['type'] for f in findings]
        self.assertIn('IP_BASED_URL', types)

    def test_shortener_detection(self):
        score, findings = self.reputation.analyze_url('https://bit.ly/abc123')
        types = [f['type'] for f in findings]
        self.assertIn('URL_SHORTENER', types)

    def test_suspicious_tld(self):
        score, findings = self.reputation.analyze_url('https://phishing.xyz/verify')
        types = [f['type'] for f in findings]
        self.assertIn('SUSPICIOUS_TLD', types)

    def test_at_symbol(self):
        score, findings = self.reputation.analyze_url('https://paypal.com@evil.com/login')
        types = [f['type'] for f in findings]
        self.assertIn('URL_AT_SYMBOL', types)

    def test_redirect_param(self):
        score, findings = self.reputation.analyze_url('https://legit.com/redirect?url=evil.com')
        types = [f['type'] for f in findings]
        self.assertIn('URL_REDIRECT', types)

    def test_clean_url(self):
        score, findings = self.reputation.analyze_url('https://www.google.com/search?q=test')
        self.assertEqual(score, 0)

    def test_urlhaus_check(self):
        result = self.reputation.check_urlhaus('http://example.com')
        self.assertIn('found', result)


if __name__ == '__main__':
    unittest.main()

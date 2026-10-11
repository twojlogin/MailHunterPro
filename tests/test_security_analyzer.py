"""Testy SecurityAnalyzer - MailHunterPro"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.security_analyzer import SecurityAnalyzer
from core.database import MailHunterDB
from core.config import MailHunterConfig

def test_phishing_detection():
    """Test wykrywania phishingu"""
    config = MailHunterConfig()
    db = MailHunterDB(":memory:")
    analyzer = SecurityAnalyzer(config, db)
    
    test_email = {
        'headers': {'From': 'security@bank.com', 'Subject': 'URGENT: Verify your account'},
        'body': {'text': 'Click here immediately or your account will be suspended', 'html': ''},
        'links': [{'url': 'http://bit.ly/fake-bank', 'text': 'Click here', 'suspicious': True}],
        'attachments': [],
        'analysis': {'suspicious_score': 0, 'flags': []}
    }
    
    result = analyzer.analyze_email(test_email)
    assert result['analysis']['suspicious_score'] > 30, "Should detect phishing"
    print("✅ Phishing detection OK")

def test_clean_email():
    """Test czystego emaila"""
    config = MailHunterConfig()
    db = MailHunterDB(":memory:")
    analyzer = SecurityAnalyzer(config, db)
    
    clean_email = {
        'headers': {'From': 'friend@gmail.com', 'Subject': 'Meeting tomorrow'},
        'body': {'text': 'Hey, can we meet at 3pm?', 'html': ''},
        'links': [],
        'attachments': [],
        'analysis': {'suspicious_score': 0, 'flags': []}
    }
    
    result = analyzer.analyze_email(clean_email)
    assert result['analysis']['suspicious_score'] < 20, "Clean email should have low score"
    print("✅ Clean email OK")

def test_xss_detection():
    """Test wykrywania XSS"""
    config = MailHunterConfig()
    db = MailHunterDB(":memory:")
    analyzer = SecurityAnalyzer(config, db)
    
    xss_email = {
        'headers': {'From': 'test@test.com', 'Subject': 'Test'},
        'body': {'text': '<script>alert("xss")</script>', 'html': ''},
        'links': [],
        'attachments': [],
        'analysis': {'suspicious_score': 0, 'flags': []}
    }
    
    result = analyzer.analyze_email(xss_email)
    assert result['analysis']['suspicious_score'] > 20, "Should detect XSS"
    print("✅ XSS detection OK")

def test_blacklist():
    """Test czarnej listy"""
    config = MailHunterConfig()
    db = MailHunterDB(":memory:")
    analyzer = SecurityAnalyzer(config, db)
    
    db.add_to_blacklist('email', 'spammer@evil.com')
    
    blacklisted_email = {
        'headers': {'From': 'spammer@evil.com', 'Subject': 'Test'},
        'body': {'text': 'Normal content', 'html': ''},
        'links': [],
        'attachments': [],
        'analysis': {'suspicious_score': 0, 'flags': []}
    }
    
    result = analyzer.analyze_email(blacklisted_email)
    assert 'BLACKLISTED_SENDER' in result['analysis']['flags']
    print("✅ Blacklist OK")

if __name__ == "__main__":
    test_phishing_detection()
    test_clean_email()
    test_xss_detection()
    test_blacklist()
    print("\n✅ Wszystkie testy przeszły!")

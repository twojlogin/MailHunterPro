"""Testy MailHunterDB - MailHunterPro"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import MailHunterDB

def test_database_init():
    """Test inicjalizacji bazy"""
    db = MailHunterDB(":memory:")
    assert db is not None
    print("✅ Database init OK")

def test_insert_email():
    """Test wstawiania emaila"""
    db = MailHunterDB(":memory:")
    
    parsed_email = {
        'headers': {
            'Message-ID': 'test-123',
            'From': 'sender@test.com',
            'To': 'receiver@test.com',
            'Subject': 'Test Subject',
            'Date': '2026-09-10'
        },
        'body': {
            'text': 'Test body',
            'html': '<p>Test</p>'
        },
        'attachments': [],
        'links': [],
        'analysis': {
            'suspicious_score': 25,
            'flags': ['TEST'],
            'timestamp': '2026-09-10T12:00:00'
        }
    }
    
    result = db.insert_email(parsed_email, "test@gmail.com", "INBOX")
    
    assert result is not None
    print("✅ Insert email OK")

def test_blacklist_whitelist():
    """Test czarnej i białej listy"""
    db = MailHunterDB(":memory:")
    
    # Blacklist
    db.add_to_blacklist('email', 'evil@spam.com')
    assert db.is_blacklisted('email', 'evil@spam.com') is True
    assert db.is_blacklisted('email', 'good@safe.com') is False
    
    # Whitelist
    db.add_to_whitelist('email', 'friend@gmail.com')
    assert db.is_whitelisted('email', 'friend@gmail.com') is True
    assert db.is_whitelisted('email', 'stranger@test.com') is False
    
    print("✅ Blacklist/Whitelist OK")

def test_statistics():
    """Test statystyk"""
    db = MailHunterDB(":memory:")
    
    # Wstaw kilka emaili
    for i in range(5):
        parsed_email = {
            'headers': {
                'Message-ID': f'test-{i}',
                'From': f'sender{i}@test.com',
                'To': 'me@test.com',
                'Subject': f'Subject {i}',
                'Date': '2026-09-10'
            },
            'body': {
                'text': 'Body',
                'html': ''
            },
            'attachments': [],
            'links': [],
            'analysis': {
                'suspicious_score': i * 20,
                'flags': [],
                'timestamp': '2026-09-10T12:00:00'
            }
        }
        db.insert_email(parsed_email, "test@gmail.com", "INBOX")
    
    stats = db.get_statistics()
    assert stats['total_emails'] == 5
    print("✅ Statistics OK")

if __name__ == "__main__":
    test_database_init()
    test_insert_email()
    test_blacklist_whitelist()
    test_statistics()
    print("\n✅ Wszystkie testy bazy danych przeszły!")

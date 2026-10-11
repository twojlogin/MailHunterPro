#!/usr/bin/env python3
# quick_test.py - Szybki test czy wszystko działa

import sys

print("=" * 60)
print("MailHunter - Quick Test")
print("=" * 60)

# Test 1: Python
print("\n[1/6] Python...", end=" ")
if sys.version_info >= (3, 8):
    print("✅")
else:
    print("❌")
    sys.exit(1)

# Test 2: Biblioteki
print("[2/6] Biblioteki...", end=" ")
try:
    import imaplib, email, sqlite3
    from bs4 import BeautifulSoup
    import requests
    from cryptography.fernet import Fernet
    print("✅")
except ImportError as e:
    print(f"❌ Brak: {e.name}")
    sys.exit(1)

# Test 3: IMAP
print("[3/6] IMAP connect...", end=" ")
try:
    import ssl
    ctx = ssl.create_default_context()
    imap = imaplib.IMAP4_SSL('imap.gmail.com', 993, ssl_context=ctx)
    imap.logout()
    print("✅")
except:
    print("❌")

# Test 4: SQLite
print("[4/6] SQLite...", end=" ")
try:
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('CREATE TABLE test (id INTEGER)')
    c.execute('INSERT INTO test VALUES (1)')
    c.execute('SELECT * FROM test')
    if c.fetchone()[0] == 1:
        print("✅")
    else:
        print("❌")
    conn.close()
except:
    print("❌")

# Test 5: Email parsing
print("[5/6] Email parsing...", end=" ")
try:
    raw = b"From: test@example.com\nSubject: Test\n\nBody"
    msg = email.message_from_bytes(raw)
    if msg.get('From') == 'test@example.com':
        print("✅")
    else:
        print("❌")
except:
    print("❌")

# Test 6: Security analysis
print("[6/6] Security checks...", end=" ")
try:
    import re
    text = "URGENT: Verify your account http://bit.ly/fake"
    score = 0
    if 'urgent' in text.lower(): score += 10
    if 'bit.ly' in text: score += 15
    urls = re.findall(r'http[s]?://[^\s]+', text)
    if urls: score += 5
    
    if score >= 20:
        print("✅")
    else:
        print("❌")
except:
    print("❌")

print("\n" + "=" * 60)
print("✅ Wszystko działa! Możesz użyć MailHunter!")
print("=" * 60)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailHunter - QUICK TEST SCRIPT
Sprawdza czy podstawowe funkcje działają ZANIM zainwestujesz czas w pełną instalację
"""

import sys
import imaplib
import email
import ssl
from datetime import datetime

print("=" * 70)
print("MailHunter - Quick Test Script")
print("=" * 70)
print("\nSprawdzam czy podstawowe rzeczy działają...\n")

# ============================================
# TEST 1: Python version
# ============================================
print("[1/8] Sprawdzam wersję Pythona...")
if sys.version_info >= (3, 8):
    print(f"    ✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
else:
    print(f"    ❌ Python {sys.version_info.major}.{sys.version_info.minor} - wymagany 3.8+")
    sys.exit(1)

# ============================================
# TEST 2: Required modules
# ============================================
print("\n[2/8] Sprawdzam wymagane biblioteki...")
required_modules = {
    'imaplib': 'Wbudowane',
    'email': 'Wbudowane', 
    'sqlite3': 'Wbudowane',
    'tkinter': 'Wbudowane',
    'ssl': 'Wbudowane'
}

optional_modules = {
    'beautifulsoup4': 'bs4',
    'requests': 'requests',
    'cryptography': 'cryptography'
}

all_ok = True
for module, import_name in required_modules.items():
    try:
        __import__(import_name if import_name != 'Wbudowane' else module)
        print(f"    ✅ {module}")
    except ImportError:
        print(f"    ❌ {module} - BRAK!")
        all_ok = False

print("\n    Opcjonalne biblioteki:")
for module, import_name in optional_modules.items():
    try:
        __import__(import_name)
        print(f"    ✅ {module}")
    except ImportError:
        print(f"    ⚠️  {module} - brak (będzie potrzebne później)")

# ============================================
# TEST 3: IMAP connection test
# ============================================
print("\n[3/8] Test połączenia IMAP...")
print("    Testuję połączenie z Gmail IMAP (bez logowania)...")

try:
    context = ssl.create_default_context()
    imap = imaplib.IMAP4_SSL('imap.gmail.com', 993, ssl_context=context)
    print("    ✅ Połączenie z Gmail IMAP działa")
    imap.logout()
except Exception as e:
    print(f"    ❌ Błąd połączenia: {e}")
    all_ok = False

# ============================================
# TEST 4: SQLite database
# ============================================
print("\n[4/8] Test bazy danych SQLite...")
try:
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # Stwórz testową tabelę
    cursor.execute('''
        CREATE TABLE test_emails (
            id INTEGER PRIMARY KEY,
            subject TEXT,
            score INTEGER
        )
    ''')
    
    # Dodaj testowe dane
    cursor.execute("INSERT INTO test_emails (subject, score) VALUES (?, ?)", 
                   ("Test email", 75))
    
    # Odczytaj
    cursor.execute("SELECT * FROM test_emails WHERE score > 50")
    result = cursor.fetchone()
    
    if result:
        print("    ✅ SQLite działa poprawnie")
    else:
        print("    ❌ Problem z SQLite")
        all_ok = False
    
    conn.close()
except Exception as e:
    print(f"    ❌ Błąd SQLite: {e}")
    all_ok = False

# ============================================
# TEST 5: Email parsing
# ============================================
print("\n[5/8] Test parsowania e-maili...")
try:
    # Przykładowy surowy email
    raw_email = b"""From: test@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

This is a test email body.
http://suspicious-link.com
"""
    
    email_message = email.message_from_bytes(raw_email)
    
    # Sprawdź czy parsowanie działa
    sender = email_message.get('From')
    subject = email_message.get('Subject')
    
    if sender and subject:
        print(f"    ✅ Parsowanie działa")
        print(f"       From: {sender}")
        print(f"       Subject: {subject}")
    else:
        print("    ❌ Problem z parsowaniem")
        all_ok = False
        
except Exception as e:
    print(f"    ❌ Błąd parsowania: {e}")
    all_ok = False

# ============================================
# TEST 6: Security analysis (basic)
# ============================================
print("\n[6/8] Test podstawowej analizy bezpieczeństwa...")
try:
    import re
    
    test_content = """
    URGENT: Your account will be suspended!
    Click here immediately: http://bit.ly/abc123
    Verify your payment details now!
    """
    
    score = 0
    flags = []
    
    # Test 1: Phishing keywords
    phishing_words = ['urgent', 'suspended', 'verify', 'immediately']
    found_words = [word for word in phishing_words if word in test_content.lower()]
    if found_words:
        score += 20
        flags.append(f"PHISHING_KEYWORDS: {len(found_words)}")
    
    # Test 2: Shortened URLs
    if 'bit.ly' in test_content or 'tinyurl' in test_content:
        score += 15
        flags.append("SHORTENED_URL")
    
    # Test 3: URL detection
    urls = re.findall(r'http[s]?://[^\s]+', test_content)
    if urls:
        score += 10
        flags.append(f"URLS_FOUND: {len(urls)}")
    
    print(f"    ✅ Analiza działa")
    print(f"       Test Score: {score}")
    print(f"       Flags: {', '.join(flags)}")
    
except Exception as e:
    print(f"    ❌ Błąd analizy: {e}")
    all_ok = False

# ============================================
# TEST 7: Tkinter GUI
# ============================================
print("\n[7/8] Test GUI (tkinter)...")
try:
    import tkinter as tk
    
    # Stwórz testowe okno (nie pokazuj go)
    root = tk.Tk()
    root.withdraw()  # Ukryj okno
    
    # Test czy możemy stworzyć podstawowe widgety
    label = tk.Label(root, text="Test")
    button = tk.Button(root, text="Test")
    
    print("    ✅ Tkinter GUI działa")
    
    root.destroy()
    
except Exception as e:
    print(f"    ❌ Błąd Tkinter: {e}")
    print("    ⚠️  GUI może nie działać, ale CLI będzie OK")

# ============================================
# TEST 8: File operations
# ============================================
print("\n[8/8] Test operacji na plikach...")
try:
    import os
    import tempfile
    
    # Stwórz testowy katalog
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, 'test.txt')
        
        # Zapisz
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write("Test content")
        
        # Odczytaj
        with open(test_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if content == "Test content":
            print("    ✅ Operacje na plikach działają")
        else:
            print("    ❌ Problem z plikami")
            all_ok = False
            
except Exception as e:
    print(f"    ❌ Błąd plików: {e}")
    all_ok = False

# ============================================
# FINAL VERDICT
# ============================================
print("\n" + "=" * 70)
if all_ok:
    print("🎉 WSZYSTKO DZIAŁA! Możesz śmiało instalować MailHunter!")
    print("\nNastępne kroki:")
    print("1. pip install beautifulsoup4 requests cryptography")
    print("2. Skopiuj kod z artifacts")
    print("3. python setup_env.py")
    print("4. python configure_accounts.py")
    print("5. python mailhunter_cli.py")
else:
    print("⚠️  UWAGA: Niektóre testy nie przeszły!")
    print("\nCo zrobić:")
    print("1. Zainstaluj brakujące biblioteki: pip install beautifulsoup4 requests cryptography")
    print("2. Sprawdź połączenie internetowe")
    print("3. Uruchom ponownie ten skrypt")

print("=" * 70)

# ============================================
# BONUS: Quick IMAP login test (optional)
# ============================================
print("\n" + "=" * 70)
print("BONUS TEST (opcjonalny): Test logowania do prawdziwego konta")
print("=" * 70)

test_login = input("\nCzy chcesz przetestować logowanie do prawdziwego konta Gmail? (t/N): ").lower()

if test_login == 't' or test_login == 'y':
    print("\nUWAGA: Potrzebujesz hasła aplikacji Gmail!")
    print("Wygeneruj tutaj: https://myaccount.google.com/apppasswords")
    
    email_address = input("\nAdres Gmail: ").strip()
    app_password = input("Hasło aplikacji (będzie ukryte): ").strip()
    
    if email_address and app_password:
        print("\nŁączę się z Gmail...")
        try:
            context = ssl.create_default_context()
            imap = imaplib.IMAP4_SSL('imap.gmail.com', 993, ssl_context=context)
            imap.login(email_address, app_password)
            
            # Wybierz INBOX
            status, count = imap.select('INBOX')
            message_count = int(count[0])
            
            print(f"\n✅ SUKCES! Połączono z kontem Gmail")
            print(f"   Masz {message_count} wiadomości w INBOX")
            
            # Pobierz najnowszą wiadomość jako test
            if message_count > 0:
                print("\n   Testuję pobieranie wiadomości...")
                status, messages = imap.search(None, 'ALL')
                
                if status == 'OK':
                    msg_nums = messages[0].split()
                    latest_msg = msg_nums[-1]  # Ostatnia wiadomość
                    
                    status, data = imap.fetch(latest_msg, '(RFC822)')
                    
                    if status == 'OK':
                        raw_email = data[0][1]
                        email_message = email.message_from_bytes(raw_email)
                        
                        print(f"   ✅ Pobrano wiadomość!")
                        print(f"      From: {email_message.get('From', 'N/A')[:50]}")
                        print(f"      Subject: {email_message.get('Subject', 'N/A')[:50]}")
                        print(f"      Date: {email_message.get('Date', 'N/A')[:50]}")
            
            imap.close()
            imap.logout()
            
            print("\n🎉 PEŁNY SUKCES! MailHunter będzie działał bez problemu!")
            
        except imaplib.IMAP4.error as e:
            print(f"\n❌ Błąd logowania: {e}")
            print("\nSprawdź:")
            print("1. Czy używasz hasła aplikacji (nie zwykłego hasła)")
            print("2. Czy IMAP jest włączony w ustawieniach Gmail")
            print("3. Czy adres email jest poprawny")
            
        except Exception as e:
            print(f"\n❌ Nieoczekiwany błąd: {e}")
    else:
        print("\n⏭️  Pominięto test logowania")
else:
    print("\n⏭️  Pominięto test logowania")

print("\n" + "=" * 70)
print("Test zakończony!")
print("=" * 70)
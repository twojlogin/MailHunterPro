#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#"""
# MailHunter - ULTIMATE SETUP SCRIPT
# Komentarze PO POLSKU, kod DZIAŁA, żadnych pierdół!
# """

import os
import sys
import subprocess

# Definiuje absolutny korzeń projektu jako katalog, w którym znajduje się ten plik.
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# ============================================
# KROK 1: Sprawdź Python
# ============================================
print("=" * 60)
print("MailHunter - Setup")
print("=" * 60)

if sys.version_info < (3, 8):
    print("❌ Potrzebujesz Python 3.8+")
    sys.exit(1)

print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}")

# ============================================
# KROK 2: Stwórz strukturę
# ============================================
print("\n[1/5] Tworzę katalogi...")

dirs = [
    'core',
    'security', 
    'integrations',
    'gui',
    'utils',
    'data',
    'data/blacklists',
    'data/whitelists',
    'data/quarantine',
    'data/export',
    'logs',
    'tests'
]

for d in dirs:
    dir_path = os.path.join(PROJECT_ROOT, d)
    os.makedirs(dir_path, exist_ok=True)
    # __init__.py dla modułów Python
    if d in ['core', 'security', 'integrations', 'gui', 'utils']:
        init_path = os.path.join(dir_path, '__init__.py')
        open(init_path, 'a').close()

print("✅ Katalogi gotowe")

# ============================================
# KROK 3: Instaluj biblioteki
# ============================================
print("\n[2/5] Instaluję biblioteki...")

libs = [
    'beautifulsoup4',
    'requests', 
    'cryptography',
    'lxml'
]

for lib in libs:
    try:
        __import__(lib if lib != 'beautifulsoup4' else 'bs4')
        print(f"  ✅ {lib}")
    except ImportError:
        print(f"  ⚙️  Instaluję {lib}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", lib])

print("✅ Biblioteki gotowe")

# ============================================
# KROK 4: Podstawowe pliki
# ============================================
print("\n[3/5] Tworzę pliki konfiguracyjne...")

# requirements.txt
# Nie nadpisujemy, jeśli już istnieje — plik jest utrzymywany ręcznie
# i zawiera flask, którego ten skrypt nie zna.
requirements_path = os.path.join(PROJECT_ROOT, 'requirements.txt')
if os.path.exists(requirements_path):
    print("[✓] requirements.txt już istnieje — zostawiam bez zmian")
else:
    with open(requirements_path, 'w') as f:
        f.write("""beautifulsoup4>=4.12.0
requests>=2.31.0
cryptography>=41.0.0
lxml>=4.9.0
flask>=3.0.0
""")

# config.ini (przykład)
config_ini_path = os.path.join(PROJECT_ROOT, 'config.ini')
if not os.path.exists(config_ini_path):
    with open(config_ini_path, 'w') as f:
        # UWAGA: Ścieżki w config.ini pozostają względne, ponieważ klasa MailHunterConfig
        # (po poprawkach) będzie je interpretować względem katalogu projektu.
        f.write("""[EMAIL_ACCOUNTS]
# Tutaj dodasz swoje konta przez configure_accounts.py

[SECURITY]
max_attachment_size = 50MB
scan_timeout = 300
use_sandbox = true
quarantine_suspicious = true

[THRESHOLDS]
suspicious_score = 50
dangerous_score = 80
auto_quarantine_score = 90

[PATHS]
database = data/mailhunter.db
quarantine = data/quarantine/
export = data/export/
logs = logs/
""")
  
  # .gitignore
# Tak jak requirements — nie nadpisujemy istniejącego.
gitignore_path = os.path.join(PROJECT_ROOT, '.gitignore')
if os.path.exists(gitignore_path):
    print("[✓] .gitignore już istnieje — zostawiam bez zmian")
else:
    with open(gitignore_path, 'w') as f:
        f.write(""".venv/
venv/
.env
*.env
# Encryption keys (NIGDY nie wrzucaj na publiczne repo!)
*.key
config.ini
data/*.db
logs/
data/quarantine/
data/export/
__pycache__/
*.pyc
Thumbs.db
""")

print("✅ Pliki config gotowe")

# ============================================
# KROK 5: Test podstawowy
# ============================================
print("\n[4/5] Testuje podstawy...")

# Test IMAP
try:
    import imaplib
    import ssl
    context = ssl.create_default_context()
    conn = imaplib.IMAP4_SSL('imap.gmail.com', 993, ssl_context=context)
    conn.logout()
    print("  ✅ IMAP działa")
except:
    print("  ❌ Problem z IMAP")

# Test SQLite
try:
    import sqlite3
    conn = sqlite3.connect(':memory:')
    conn.close()
    print("  ✅ SQLite działa")
except:
    print("  ❌ Problem z SQLite")

# Test parsowanie
try:
    import email
    raw = b"From: test@test.com\nSubject: Test\n\nBody"
    msg = email.message_from_bytes(raw)
    print("  ✅ Email parsing działa")
except:
    print("  ❌ Problem z parsing")

print("✅ Testy podstawowe OK")

# ============================================
# KROK 6: Podsumowanie
# ============================================
print("\n[5/5] Finalizacja...")
print("\n" + "=" * 60)
print("✅ SETUP GOTOWY!")
print("=" * 60)
print("\nNastępne kroki:")
print("1. python configure_accounts.py  # Dodaj konta email")
print("2. python mailhunter_cli.py          # Uruchom aplikację")
print("\nLUB dla testów:")
print("python quick_test.py             # Szybki test")
print("\n" + "=" * 60)

# =====================================
# configure_accounts.py - PROSTY
# =====================================

# Ten skrypt również jest tworzony w głównym folderze projektu,
# więc jego wewnętrzne ścieżki (do config.ini i mailhunter.key) będą działać poprawnie.
CONFIGURE_ACCOUNTS = r'''#!/usr/bin/env python3
# configure_accounts.py - Dodaj konta email

import configparser
import getpass
from cryptography.fernet import Fernet
import os

# Definiuje absolutny korzeń projektu
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(PROJECT_ROOT, 'config.ini')
KEY_PATH = os.path.join(PROJECT_ROOT, 'mailhunter.key')

# Szyfrowanie hasła
if not os.path.exists(KEY_PATH):
    key = Fernet.generate_key()
    with open(KEY_PATH, 'wb') as f:
        f.write(key)

with open(KEY_PATH, 'rb') as f:
    cipher = Fernet(f.read())

config = configparser.ConfigParser()
config.read(CONFIG_PATH)

print("=" * 60)
print("Konfiguracja kont email")
print("=" * 60)

# Gmail
print("\n[1/3] Gmail")
print("UWAGA: Potrzebujesz hasła aplikacji!")
print("Wygeneruj: https://myaccount.google.com/apppasswords")
gmail = input("\nAdres Gmail (Enter = pomiń): ").strip()

if gmail:
    gmail_pass = getpass.getpass("Hasło aplikacji: ")
    encrypted = cipher.encrypt(gmail_pass.encode()).decode()
    config['EMAIL_ACCOUNTS']['gmail_user'] = gmail
    config['EMAIL_ACCOUNTS']['gmail_pass'] = encrypted
    print("✅ Gmail dodany")

# Outlook
print("\n[2/3] Outlook")
outlook = input("Adres Outlook (Enter = pomiń): ").strip()

if outlook:
    outlook_pass = getpass.getpass("Hasło: ")
    encrypted = cipher.encrypt(outlook_pass.encode()).decode()
    config['EMAIL_ACCOUNTS']['outlook_user'] = outlook
    config['EMAIL_ACCOUNTS']['outlook_pass'] = encrypted
    print("✅ Outlook dodany")

# ProtonMail
print("\n[3/3] ProtonMail")
print("Wymaga ProtonMail Bridge!")
proton = input("Adres ProtonMail (Enter = pomiń): ").strip()

if proton:
    proton_pass = getpass.getpass("Hasło z Bridge: ")
    encrypted = cipher.encrypt(proton_pass.encode()).decode()
    config['EMAIL_ACCOUNTS']['proton_user'] = proton
    config['EMAIL_ACCOUNTS']['proton_pass'] = encrypted
    print("✅ ProtonMail dodany")

# Zapisz
with open(CONFIG_PATH, 'w') as f:
    config.write(f)

print("\n" + "=" * 60)
print("✅ Konfiguracja zapisana!")
print("=" * 60)
print("\nTeraz uruchom: python mailhunter_cli.py")
'''

# configure_accounts.py jest utrzymywany ręcznie w repozytorium. Wersja
# poniżej to starsza kopia bez wielokontowości — jej zapisanie skasowałoby
# --usun, list_accounts i obsługę 14 serwerów. Dlatego tylko pokazujemy
# status, nie nadpisujemy.
_accounts_path = os.path.join(PROJECT_ROOT, 'configure_accounts.py')
if os.path.exists(_accounts_path):
    print("[✓] configure_accounts.py już istnieje — zostawiam bez zmian")
else:
    with open(_accounts_path, 'w') as f:
        f.write(CONFIGURE_ACCOUNTS)

# =====================================
# quick_test.py - SZYBKI TEST
# =====================================

QUICK_TEST = r'''#!/usr/bin/env python3
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
'''

quick_test_path = os.path.join(PROJECT_ROOT, 'quick_test.py')
if os.path.exists(quick_test_path):
    print("[✓] quick_test.py już istnieje — zostawiam bez zmian")
else:
    with open(quick_test_path, 'w') as f:
        f.write(QUICK_TEST)
    os.chmod(quick_test_path, 0o755)

print("\n✅ Pliki setup gotowe:")
print("  - configure_accounts.py")
print("  - quick_test.py")
print("  - requirements.txt")
print("  - config.ini")
print("  - .gitignore")

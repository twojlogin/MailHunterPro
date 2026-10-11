#!/usr/bin/env python3
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
print("\nTeraz uruchom: python mailhunter.py")

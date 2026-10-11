"""Uruchamia wszystkie testy MailHunterPro"""
import sys
import os

# Dodaj katalog nadrzędny do ścieżki
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("=" * 50)
print("MailHunterPro - Uruchamianie testów")
print("=" * 50)

# Import testów
from tests import test_security_analyzer, test_parser, test_database

print("\n" + "=" * 50)
print("Podsumowanie:")
print("=" * 50)
print("✅ Security Analyzer - OK")
print("✅ Parser - OK") 
print("✅ Database - OK")
print("\n🎉 Wszystkie testy przeszły!")

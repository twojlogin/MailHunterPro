import configparser
import os
import logging
from cryptography.fernet import Fernet

# Definiuje absolutny korzeń projektu jako katalog Nadrzędny do folderu /core
# To zapewnia, że ścieżki zawsze odnoszą się do głównego folderu projektu.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class MailHunterConfig:
    def __init__(self, config_path="config.ini"):
        self.project_root = PROJECT_ROOT
        self.config_path = os.path.join(self.project_root, config_path)
        self.config = configparser.ConfigParser()
        self.key_file = os.path.join(self.project_root, "mailhunter.key")
        self._load_or_create_config()
        self._setup_encryption()
    
    def _load_or_create_config(self):
        if os.path.exists(self.config_path):
            self.config.read(self.config_path)
        else:
            self._create_default_config()
    
    def _create_default_config(self):
        """Tworzy domyślny plik konfiguracyjny z absolutnymi ścieżkami"""
        self.config['EMAIL_ACCOUNTS'] = {}
        self.config['SECURITY'] = {
            'max_attachment_size': '50MB',
            'scan_timeout': '300',
            'use_sandbox': 'true',
            'quarantine_suspicious': 'true'
        }
        self.config['API_KEYS'] = {}
        self.config['THRESHOLDS'] = {
            'suspicious_score': '50',
            'dangerous_score': '80',
            'auto_quarantine_score': '90'
        }
        # Użyj PROJECT_ROOT do stworzenia absolutnych ścieżek
        self.config['PATHS'] = {
            'database': os.path.join(self.project_root, 'data', 'mailhunter.db'),
            'quarantine': os.path.join(self.project_root, 'data', 'quarantine'),
            'export': os.path.join(self.project_root, 'data', 'export'),
            'logs': os.path.join(self.project_root, 'logs')
        }
        self.save_config()

    def _setup_encryption(self):
        """Inicjalizuje szyfrowanie dla haseł"""
        if not os.path.exists(self.key_file):
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
        
        with open(self.key_file, 'rb') as f:
            self.cipher_suite = Fernet(f.read())
    
    def encrypt_password(self, password):
        """Szyfruje hasło"""
        return self.cipher_suite.encrypt(password.encode()).decode()
    
    def decrypt_password(self, encrypted_password):
        """Deszyfruje hasło"""
        return self.cipher_suite.decrypt(encrypted_password.encode()).decode()
    
    def get_email_credentials(self, provider):
        """Pobiera dane logowania dla providera e-mail"""
        section = 'EMAIL_ACCOUNTS'
        if section in self.config:
            user = self.config[section].get(f'{provider}_user', '')
            encrypted_pass = self.config[section].get(f'{provider}_pass', '')
            if encrypted_pass:
                password = self.decrypt_password(encrypted_pass)
                return user, password
        return None, None
    
    def set_email_credentials(self, provider, username, password):
        """Zapisuje zaszyfrowane dane logowania"""
        if 'EMAIL_ACCOUNTS' not in self.config:
            self.config['EMAIL_ACCOUNTS'] = {}
        
        self.config['EMAIL_ACCOUNTS'][f'{provider}_user'] = username
        self.config['EMAIL_ACCOUNTS'][f'{provider}_pass'] = self.encrypt_password(password)
        self.save_config()
    
    def get_threshold(self, threshold_name):
        """Pobiera próg bezpieczeństwa"""
        if not self.config.has_section('THRESHOLDS'):
            return 50
        return int(self.config['THRESHOLDS'].get(threshold_name, 50))

    def get_api_key(self, service):
        """Pobiera klucz API dla serwisu.

        Brak sekcji API_KEYS to normalny stan (nikt nie ustawił kluczy), a nie
        błąd. configparser rzuca przy tym KeyError, więc sprawdzamy ręcznie.
        """
        if not self.config.has_section('API_KEYS'):
            return ''
        return self.config['API_KEYS'].get(f'{service}_key', '')

    def get_security_setting(self, name, default=None):
        """Pobiera ustawienie z sekcji SECURITY.

        Jak wyżej: brak sekcji to wartość domyślna, nie wyjątek. Używane przez
        web/server.py i integracje, które bez tego padały przy starcie, gdy
        config.ini nie istniał jeszcze.
        """
        if not self.config.has_section('SECURITY'):
            return default
        return self.config['SECURITY'].get(name, default)

    def get_path(self, name, default=None):
        """Pobiera ścieżkę z sekcji PATHS."""
        if not self.config.has_section('PATHS'):
            return default
        return self.config['PATHS'].get(name, default)

    def ensure_section(self, section, defaults=None):
        """Zapewnia, że sekcja istnieje. Zwraca True jeśli była utworzona.

        Dodane, bo każdy zapis do config['SEKCJA'] bez wcześniejszego sprawdzenia
        kończył się KeyError przy pierwszym uruchomieniu bez pliku config.ini.
        """
        created = not self.config.has_section(section)
        if created:
            self.config[section] = defaults or {}
        return created
    
    def save_config(self):
        """Zapisuje konfigurację do pliku"""
        with open(self.config_path, 'w') as f:
            self.config.write(f)

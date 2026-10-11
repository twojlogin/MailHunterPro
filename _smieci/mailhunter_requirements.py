# requirements.txt
# MailHunter Dependencies

# Core email handling
imaplib3==0.5.2
email-validator==1.3.1

# HTML/XML parsing
beautifulsoup4==4.12.2
lxml==4.9.3

# HTTP requests
requests==2.31.0

# Encryption
cryptography==41.0.4

# WHOIS queries
python-whois==0.8.0

# Data processing
pandas==2.0.3

# Optional: Advanced GUI
# PyQt5==5.15.9

# Optional: OCR
# pytesseract==0.3.10
# pillow==10.0.0

# Optional: Plotting
# matplotlib==3.7.2

# Optional: AI integrations
# openai==0.28.0
# anthropic==0.3.0

# Optional: File processing
# openpyxl==3.1.2
# python-docx==0.8.11

# Testing
pytest==7.4.0
pytest-cov==4.1.0

# =====================================
# setup_env.py
"""
Skrypt konfiguracyjny środowiska MailHunter
"""

import os
import sys
import subprocess
from pathlib import Path

def create_directory_structure():
    """Tworzy strukturę katalogów projektu"""
    directories = [
        'core',
        'security',
        'integrations',
        'gui',
        'utils',
        'data',
        'data/blacklists',
        'data/whitelists',
        'data/rules',
        'data/templates',
        'data/quarantine',
        'data/export',
        'tests',
        'scripts',
        'logs'
    ]
    
    print("Tworzenie struktury katalogów...")
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        
        # Tworzenie __init__.py w katalogach Python
        if directory in ['core', 'security', 'integrations', 'gui', 'utils', 'tests']:
            init_file = Path(directory) / '__init__.py'
            init_file.touch(exist_ok=True)
    
    print("✓ Struktura katalogów utworzona")

def install_dependencies():
    """Instaluje zależności Python"""
    print("\nInstalowanie zależności...")
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ Zależności zainstalowane")
    except subprocess.CalledProcessError as e:
        print(f"✗ Błąd instalacji zależności: {e}")
        return False
    
    return True

def create_default_blacklists():
    """Tworzy domyślne listy blokowanych"""
    print("\nTworzenie domyślnych list blokujących...")
    
    # Podejrzane domeny
    suspicious_domains = [
        'example-phishing.com',
        'fake-bank.tk',
        'suspicious-site.ml'
    ]
    
    with open('data/blacklists/domains.txt', 'w') as f:
        f.write('\n'.join(suspicious_domains))
    
    # Podejrzane TLD
    suspicious_tlds = [
        '.tk', '.ml', '.ga', '.cf', '.gq'
    ]
    
    with open('data/blacklists/tlds.txt', 'w') as f:
        f.write('\n'.join(suspicious_tlds))
    
    print("✓ Listy blokujące utworzone")

def create_readme():
    """Tworzy plik README.md"""
    readme_content = """# MailHunter

Zaawansowane narzędzie do analizy bezpieczeństwa e-maili.

## Instalacja

```bash
python setup_env.py
```

## Uruchomienie

```bash
python mailhunter_cli.py
```

## Konfiguracja kont e-mail

1. Uruchom aplikację
2. Przejdź do Plik → Ustawienia
3. Dodaj dane logowania dla swoich kont

### Gmail
- Musisz utworzyć hasło aplikacji (App Password)
- Instrukcje: https://support.google.com/accounts/answer/185833

### Outlook
- Użyj standardowego hasła do konta Microsoft

### ProtonMail
- Wymaga ProtonMail Bridge
- Pobierz: https://protonmail.com/bridge/

## Funkcje

- ✅ Skanowanie IMAP (Gmail, Outlook, ProtonMail)
- ✅ Analiza nagłówków (spoofing detection)
- ✅ Detekcja phishingu
- ✅ Skanowanie załączników
- ✅ System punktacji zagrożeń
- ✅ Białe i czarne listy
- ✅ Automatyczna kwarantanna
- ⏳ Integracja z VirusTotal (w przygotowaniu)
- ⏳ Integracja z AbuseIPDB (w przygotowaniu)
- ⏳ Analiza AI (w przygotowaniu)
- ⏳ OCR skanowanie (w przygotowaniu)

## Bezpieczeństwo

- Wszystkie hasła są szyfrowane lokalnie
- Klucze API przechowywane w bezpiecznym pliku konfiguracyjnym
- Podejrzane maile mogą być analizowane w Windows Sandbox
- Wszystkie operacje są logowane

## Licencja

MIT License
"""
    
    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    print("✓ README.md utworzony")

def create_gitignore():
    """Tworzy plik .gitignore"""
    gitignore_content = """# MailHunter .gitignore

# Konfiguracja i klucze
config.ini
mailhunter.key
*.key

# Baza danych
*.db
*.sqlite
*.sqlite3

# Logi
logs/
*.log

# Dane użytkownika
data/quarantine/
data/export/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
ENV/
env/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db
"""
    
    with open('.gitignore', 'w') as f:
        f.write(gitignore_content)
    
    print("✓ .gitignore utworzony")

def main():
    """Główna funkcja setup"""
    print("=" * 60)
    print("MailHunter - Setup Environment")
    print("=" * 60)
    
    # Sprawdź wersję Python
    if sys.version_info < (3, 8):
        print("✗ Wymagany Python 3.8 lub nowszy!")
        sys.exit(1)
    
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}")
    
    # Tworzenie struktury
    create_directory_structure()
    
    # Instalacja zależności
    if not install_dependencies():
        print("\n⚠ Instalacja zależności nie powiodła się")
        print("Możesz spróbować ręcznie: pip install -r requirements.txt")
    
    # Tworzenie domyślnych plików
    create_default_blacklists()
    create_readme()
    create_gitignore()
    
    print("\n" + "=" * 60)
    print("✓ Setup zakończony pomyślnie!")
    print("=" * 60)
    print("\nKolejne kroki:")
    print("1. Skonfiguruj konta e-mail w aplikacji")
    print("2. Uruchom: python mailhunter_cli.py")
    print("3. Rozpocznij skanowanie!")
    print("\n")

if __name__ == "__main__":
    main()

# =====================================
# configure_accounts.py
"""
Interaktywny skrypt do konfiguracji kont e-mail
"""

import sys
import getpass
from core.config import MailHunterConfig

def configure_account(config, provider):
    """Konfiguruje pojedyncze konto"""
    print(f"\n{'='*60}")
    print(f"Konfiguracja konta: {provider.upper()}")
    print(f"{'='*60}")
    
    if provider == "gmail":
        print("\nUWAGA: Gmail wymaga hasła aplikacji (App Password)")
        print("Instrukcje: https://support.google.com/accounts/answer/185833")
    elif provider == "proton":
        print("\nUWAGA: ProtonMail wymaga ProtonMail Bridge")
        print("Pobierz: https://protonmail.com/bridge/")
    
    print()
    username = input(f"Adres e-mail ({provider}): ").strip()
    
    if not username:
        print("✗ Pominięto")
        return False
    
    password = getpass.getpass(f"Hasło dla {username}: ")
    
    if not password:
        print("✗ Pominięto")
        return False
    
    # Zapisz dane
    config.set_email_credentials(provider, username, password)
    print(f"✓ Konto {provider} skonfigurowane")
    
    return True

def test_connection(config, provider):
    """Testuje połączenie z kontem"""
    print(f"\nTestowanie połączenia z {provider}...")
    
    try:
        from core.email_client import EmailClient
        
        client = EmailClient(config)
        if client.connect(provider):
            print(f"✓ Połączenie z {provider} udane!")
            client.disconnect()
            return True
        else:
            print(f"✗ Nie można połączyć z {provider}")
            return False
    except Exception as e:
        print(f"✗ Błąd: {str(e)}")
        return False

def main():
    """Główna funkcja konfiguracji"""
    print("=" * 60)
    print("MailHunter - Konfiguracja Kont E-mail")
    print("=" * 60)
    
    config = MailHunterConfig()
    
    providers = ["gmail", "outlook", "proton"]
    
    print("\nDostępne providery:")
    for idx, provider in enumerate(providers, 1):
        print(f"{idx}. {provider.capitalize()}")
    
    print("\nSkonfiguruj konta, które chcesz używać.")
    print("Możesz pominąć konto wciskając Enter bez wpisywania danych.\n")
    
    configured = []
    
    for provider in providers:
        response = input(f"\nCzy chcesz skonfigurować {provider}? (t/N): ").strip().lower()
        
        if response == 't' or response == 'y':
            if configure_account(config, provider):
                configured.append(provider)
                
                # Opcjonalnie testuj połączenie
                test = input("Czy przetestować połączenie? (t/N): ").strip().lower()
                if test == 't' or test == 'y':
                    test_connection(config, provider)
    
    print("\n" + "=" * 60)
    if configured:
        print(f"✓ Skonfigurowano konta: {', '.join(configured)}")
    else:
        print("⚠ Nie skonfigurowano żadnego konta")
    print("=" * 60)
    print("\nMożesz teraz uruchomić MailHunter: python mailhunter_cli.py")

if __name__ == "__main__":
    main()

# =====================================
# scripts/init_sandbox.ps1
<#
.SYNOPSIS
    Skrypt inicjalizacyjny dla Windows Sandbox
    
.DESCRIPTION
    Przygotowuje środowisko Windows Sandbox do bezpiecznej analizy e-maili
#>

Write-Host "MailHunter - Windows Sandbox Initialization" -ForegroundColor Cyan
Write-Host "=" * 60

# Sprawdź czy jesteśmy w Sandbox
$isSandbox = $false
try {
    $computerName = $env:COMPUTERNAME
    if ($computerName -like "*SANDBOX*") {
        $isSandbox = $true
    }
} catch {
    $isSandbox = $false
}

if (-not $isSandbox) {
    Write-Host "UWAGA: Uruchomiono poza Windows Sandbox!" -ForegroundColor Yellow
}

# Utwórz katalogi robocze
$workDir = "C:\MailSandbox"
if (-not (Test-Path $workDir)) {
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
}

Set-Location $workDir

Write-Host "`n[1/5] Sprawdzanie środowiska..."

# Sprawdź Python
$pythonPath = Get-Command python -ErrorAction SilentlyContinue
if ($pythonPath) {
    $pythonVersion = python --version
    Write-Host "  ✓ Python dostępny: $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "  ✗ Python nie znaleziony!" -ForegroundColor Red
    Write-Host "  Pobierz WinPython i umieść w katalogu Sandbox" -ForegroundColor Yellow
}

Write-Host "`n[2/5] Konfiguracja sieci..."
# Sprawdź połączenie internetowe
$ping = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet
if ($ping) {
    Write-Host "  ✓ Połączenie internetowe aktywne" -ForegroundColor Green
} else {
    Write-Host "  ✗ Brak połączenia internetowego" -ForegroundColor Red
}

Write-Host "`n[3/5] Montowanie katalogów..."
# Sprawdź zamontowane katalogi
if (Test-Path "D:\MailSandbox") {
    Write-Host "  ✓ Katalog D:\MailSandbox dostępny" -ForegroundColor Green
    
    # Skopiuj niezbędne pliki
    if (Test-Path "D:\MailSandbox\MailHunter") {
        Copy-Item -Path "D:\MailSandbox\MailHunter\*" -Destination $workDir -Recurse -Force
        Write-Host "  ✓ Pliki MailHunter skopiowane" -ForegroundColor Green
    }
} else {
    Write-Host "  ✗ Katalog D:\MailSandbox niedostępny" -ForegroundColor Red
}

Write-Host "`n[4/5] Instalacja zależności..."
if (Test-Path "$workDir\requirements.txt") {
    try {
        python -m pip install -q -r requirements.txt
        Write-Host "  ✓ Zależności zainstalowane" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ Błąd instalacji zależności" -ForegroundColor Red
    }
} else {
    Write-Host "  ⚠ Brak pliku requirements.txt" -ForegroundColor Yellow
}

Write-Host "`n[5/5] Konfiguracja bezpieczeństwa..."
# Wyłącz Windows Defender (opcjonalne, dla testów)
# Set-MpPreference -DisableRealtimeMonitoring $true

Write-Host "  ✓ Środowisko gotowe do analizy" -ForegroundColor Green

Write-Host "`n" + ("=" * 60)
Write-Host "Sandbox gotowy!" -ForegroundColor Green
Write-Host "=" * 60
Write-Host "`nUruchom MailHunter: python mailhunter_cli.py`n"

# Opcjonalnie otwórz GUI
$autoStart = $env:MAILHUNTER_AUTOSTART
if ($autoStart -eq "1") {
    Write-Host "Auto-start włączony, uruchamiam MailHunter..." -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    python mailhunter_cli.py
}

# =====================================
# scripts/sandbox.wsb
<?xml version="1.0" encoding="utf-8"?>
<!--
Windows Sandbox Configuration for MailHunter
Użyj: double-click na ten plik aby uruchomić Sandbox
-->
<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>Enable</Networking>
  
  <MappedFolders>
    <MappedFolder>
      <HostFolder>D:\MailSandbox</HostFolder>
      <SandboxFolder>D:\MailSandbox</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File D:\MailSandbox\MailHunter\scripts\init_sandbox.ps1</Command>
  </LogonCommand>
  
  <MemoryInMB>4096</MemoryInMB>
</Configuration>

# =====================================
# utils/logger.py
"""
System logowania dla MailHunter
"""

import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler

class MailHunterLogger:
    def __init__(self, name="MailHunter", log_dir="logs"):
        self.name = name
        self.log_dir = log_dir
        
        # Utwórz katalog logów
        os.makedirs(log_dir, exist_ok=True)
        
        # Nazwa pliku logu
        log_filename = os.path.join(
            log_dir,
            f"mailhunter_{datetime.now().strftime('%Y%m%d')}.log"
        )
        
        # Konfiguracja loggera
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Format logów
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Handler do pliku (rotating)
        file_handler = RotatingFileHandler(
            log_filename,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        # Handler do konsoli
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # Dodaj handlery
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def get_logger(self):
        return self.logger

# =====================================
# utils/export.py
"""
Narzędzia do eksportu danych
"""

import csv
import json
from datetime import datetime
import os

class DataExporter:
    def __init__(self, database, export_dir="data/export"):
        self.database = database
        self.export_dir = export_dir
        os.makedirs(export_dir, exist_ok=True)
    
    def export_to_csv(self, threshold=0, filename=None):
        """Eksportuje wyniki do CSV"""
        if not filename:
            filename = f"mailhunter_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        filepath = os.path.join(self.export_dir, filename)
        
        # Pobierz dane
        results = self.database.get_suspicious_emails(threshold)
        
        # Zapisz do CSV
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Nagłówki
            writer.writerow(['ID', 'Sender', 'Subject', 'Score', 'Scan Date', 'Flags'])
            
            # Dane
            for row in results:
                writer.writerow(row)
        
        return filepath
    
    def export_to_json(self, threshold=0, filename=None):
        """Eksportuje wyniki do JSON"""
        if not filename:
            filename = f"mailhunter_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.export_dir, filename)
        
        # Pobierz dane
        results = self.database.get_suspicious_emails(threshold)
        
        # Konwertuj do listy słowników
        data = []
        for row in results:
            email_id, sender, subject, score, scan_date, flags = row
            data.append({
                'id': email_id,
                'sender': sender,
                'subject': subject,
                'score': score,
                'scan_date': scan_date,
                'flags': flags
            })
        
        # Zapisz do JSON
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def export_statistics(self, filename=None):
        """Eksportuje statystyki do JSON"""
        if not filename:
            filename = f"mailhunter_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.export_dir, filename)
        
        # Pobierz statystyki
        stats = self.database.get_statistics()
        stats['export_date'] = datetime.now().isoformat()
        
        # Zapisz do JSON
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
        
        return filepath
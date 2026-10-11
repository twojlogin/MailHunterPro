# MailHunter - Architektura Projektu

## 📁 Struktura Folderów

```
D:\MailSandbox\
├── MailHunter\
│   ├── core\                    # Główne moduły
│   │   ├── __init__.py
│   │   ├── email_client.py      # Obsługa IMAP/POP3
│   │   ├── parser.py            # Parsowanie wiadomości
│   │   ├── security_analyzer.py # Analiza bezpieczeństwa
│   │   ├── database.py          # SQLite operations
│   │   └── config.py            # Konfiguracja
│   │
│   ├── security\                # Moduły bezpieczeństwa
│   │   ├── __init__.py
│   │   ├── domain_checker.py    # Sprawdzanie domen/IP
│   │   ├── content_analyzer.py  # XSS, JavaScript, payloads
│   │   ├── header_analyzer.py   # Analiza nagłówków
│   │   ├── link_extractor.py    # Ekstrakcja i analiza linków
│   │   └── attachment_scanner.py # Skanowanie załączników
│   │
│   ├── integrations\            # Integracje zewnętrzne
│   │   ├── __init__.py
│   │   ├── virustotal.py        # VirusTotal API
│   │   ├── abuseipdb.py         # AbuseIPDB API
│   │   ├── ai_analyzer.py       # AI analysis (OpenAI/Claude)
│   │   └── ocr_scanner.py       # Tesseract OCR
│   │
│   ├── gui\                     # Interface użytkownika
│   │   ├── __init__.py
│   │   ├── main_window.py       # Główne okno
│   │   ├── settings_dialog.py   # Ustawienia
│   │   └── results_viewer.py    # Przeglądarka wyników
│   │
│   ├── utils\                   # Narzędzia pomocnicze
│   │   ├── __init__.py
│   │   ├── logger.py            # Logowanie
│   │   ├── encryption.py        # Szyfrowanie haseł
│   │   ├── export.py            # Eksport danych
│   │   └── sandbox.py           # Sandbox operations
│   │
│   ├── data\                    # Dane i konfiguracje
│   │   ├── blacklists\          # Listy blokowanych
│   │   ├── whitelists\          # Listy zaufanych
│   │   ├── rules\               # Reguły skanowania
│   │   └── templates\           # Szablony raportów
│   │
│   ├── tests\                   # Testy jednostkowe
│   │   ├── __init__.py
│   │   ├── test_parser.py
│   │   ├── test_security.py
│   │   └── test_integrations.py
│   │
│   ├── scripts\                 # Skrypty pomocnicze
│   │   ├── init_sandbox.ps1     # Twój istniejący skrypt
│   │   ├── setup_env.py         # Konfiguracja środowiska
│   │   └── migrate_db.py        # Migracje bazy danych
│   │
│   ├── requirements.txt         # Zależności Python
│   ├── config.ini              # Konfiguracja główna
│   ├── mailhunter.py           # Główny plik aplikacji
│   └── README.md               # Dokumentacja
```

## 🔧 Etapy Implementacji

### Etap 1: Fundament (Tydzień 1)
- **Core Email Client** - połączenia IMAP/POP3
- **Basic Parser** - parsowanie podstawowych pól
- **Simple GUI** - główne okno z podstawowymi opcjami
- **SQLite Database** - struktura bazy danych
- **Configuration System** - zarządzanie ustawieniami

### Etap 2: Bezpieczeństwo Podstawowe (Tydzień 2)
- **Domain/IP Checker** - sprawdzanie blacklist
- **Header Analyzer** - detekcja spoofingu
- **Link Extractor** - znajdowanie ukrytych linków
- **Basic Content Analysis** - XSS, JavaScript detection

### Etap 3: Analiza Zaawansowana (Tydzień 3)
- **Attachment Scanner** - analiza załączników
- **Payload Detection** - Base64, hex payloads
- **Scoring System** - system punktacji zagrożeń
- **Mail Cleaner** - hurtowe operacje

### Etap 4: Integracje Zewnętrzne (Tydzień 4)
- **VirusTotal API** - sprawdzanie linków/załączników
- **AbuseIPDB Integration** - reputacja IP
- **AI Analysis** - analiza treści z AI
- **OCR Scanner** - skanowanie obrazów

### Etap 5: Funkcje Zaawansowane (Tydzień 5)
- **Advanced GUI** - lepszy interfejs, wykresy
- **Reporting System** - generowanie raportów
- **Whitelist/Blacklist Management** - zarządzanie listami
- **Export/Import** - eksport EML, CSV, JSON

## 🛠️ Technologie i Zależności

### Python Packages
```
imaplib3==0.5.2          # IMAP client
email-validator==1.3.1    # Walidacja e-maili
beautifulsoup4==4.12.2    # HTML parsing
requests==2.31.0          # HTTP requests
sqlite3                   # Wbudowane w Python
tkinter                   # Wbudowane w Python
cryptography==41.0.4      # Szyfrowanie
python-whois==0.8.0       # WHOIS queries
pytesseract==0.3.10       # OCR
pillow==10.0.0            # Obrazy
pandas==2.0.3             # Analiza danych
matplotlib==3.7.2         # Wykresy
```

### Opcjonalne (dla zaawansowanych funkcji)
```
PyQt5==5.15.9             # Lepsze GUI
openai==0.28.0            # OpenAI API
anthropic==0.3.0          # Claude API
transformers==4.33.0      # Local LLM
scikit-learn==1.3.0       # ML algorithms
```

## 🔐 Konfiguracja Bezpieczeństwa

### Struktura config.ini
```ini
[EMAIL_ACCOUNTS]
gmail_user = encrypted_username
gmail_pass = encrypted_password
outlook_user = encrypted_username
outlook_pass = encrypted_password
proton_user = encrypted_username
proton_pass = encrypted_password

[SECURITY]
max_attachment_size = 50MB
scan_timeout = 300
use_sandbox = true
quarantine_suspicious = true

[API_KEYS]
virustotal_key = your_vt_key
abuseipdb_key = your_abuse_key
openai_key = your_openai_key

[THRESHOLDS]
suspicious_score = 50
dangerous_score = 80
auto_quarantine_score = 90
```

## 📊 System Punktacji Zagrożeń

### Kryteria Oceny (0-100 punktów)
- **Suspicious Domain**: +15 pkt
- **Spoofed Headers**: +25 pkt
- **Hidden/Shortened Links**: +10 pkt
- **JavaScript in Email**: +20 pkt
- **Base64 Payloads**: +15 pkt
- **Suspicious Attachments**: +30 pkt
- **Known Malicious IP**: +40 pkt
- **Phishing Keywords**: +20 pkt

### Poziomy Zagrożenia
- **0-30**: Bezpieczny (zielony)
- **31-50**: Podejrzany (żółty)
- **51-80**: Niebezpieczny (pomarańczowy)
- **81-100**: Bardzo niebezpieczny (czerwony)

## 🧪 Sandbox Integration

### Windows Sandbox Configuration
```xml
<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>D:\MailSandbox</HostFolder>
      <SandboxFolder>C:\MailSandbox</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\MailSandbox\scripts\init_sandbox.ps1</Command>
  </LogonCommand>
</Configuration>
```

## 🚀 Quick Start

### 1. Przygotowanie środowiska
```bash
cd D:\MailSandbox\MailHunter
pip install -r requirements.txt
python setup_env.py
```

### 2. Konfiguracja kont e-mail
```bash
python configure_accounts.py
```

### 3. Uruchomienie
```bash
python mailhunter_cli.py
```

## 📈 Roadmap Rozwoju

### Faza 1: MVP (Minimum Viable Product)
- Podstawowe skanowanie IMAP
- Proste GUI
- Eksport CSV
- Podstawowa analiza bezpieczeństwa

### Faza 2: Security Enhanced
- Integracje API
- Zaawansowana analiza
- System punktacji
- Quarantine system

### Faza 3: AI-Powered
- Analiza AI
- OCR scanning
- Predictive analysis
- Auto-learning

### Faza 4: Enterprise Ready
- Multi-user support
- API dla innych aplikacji
- Advanced reporting
- Compliance features

## 🔒 Uwagi Bezpieczeństwa

1. **Hasła** - wszystkie hasła są szyfrowane lokalnie
2. **API Keys** - przechowywane w bezpiecznym pliku konfiguracyjnym
3. **Sandbox** - podejrzane maile analizowane w izolowanym środowisku
4. **Logs** - wszystkie operacje logowane z timestampami
5. **Backup** - regularne kopie zapasowe bazy danych
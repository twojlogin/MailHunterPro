# core/simple_scanner.py
"""
Prosty skaner email - BEZ PIERDÓŁ, DZIAŁA!
"""

import imaplib
import email
import ssl
import re
import sqlite3
from datetime import datetime

class SimpleMailScanner:
    def __init__(self, server, user, password):
        self.server = server
        self.user = user
        self.password = password
        self.conn = None
        self.db = sqlite3.connect('data/mailhunter.db')
        self._init_db()
    
    def _init_db(self):
        """Prosta baza - tylko podstawy"""
        c = self.db.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY,
            sender TEXT,
            subject TEXT,
            date TEXT,
            score INTEGER,
            flags TEXT
        )''')
        self.db.commit()
    
    def connect(self):
        """Połącz z IMAP"""
        try:
            ctx = ssl.create_default_context()
            self.conn = imaplib.IMAP4_SSL(self.server, 993, ssl_context=ctx)
            self.conn.login(self.user, self.password)
            return True
        except Exception as e:
            print(f"❌ Błąd: {e}")
            return False
    
    def scan_inbox(self, limit=10):
        """Skanuj INBOX - prosty i szybki"""
        if not self.conn:
            return []
        
        self.conn.select('INBOX')
        _, messages = self.conn.search(None, 'ALL')
        
        msg_nums = messages[0].split()[-limit:]  # Ostatnie N wiadomości
        results = []
        
        for num in msg_nums:
            _, data = self.conn.fetch(num, '(RFC822)')
            raw = data[0][1]
            msg = email.message_from_bytes(raw)
            
            # Podstawowa analiza
            result = self._analyze(msg)
            results.append(result)
            
            # Zapisz do bazy
            self._save(result)
            
            print(f"{'🔴' if result['score'] >= 50 else '🟢'} {result['subject'][:40]} (score: {result['score']})")
        
        return results
    
    def _analyze(self, msg):
        """Prosta analiza - działa szybko"""
        sender = msg.get('From', '')
        subject = msg.get('Subject', '')
        
        # Treść
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='ignore')
                        break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='ignore')
        
        # Scoring - prosty ale skuteczny
        score = 0
        flags = []
        
        text = (subject + ' ' + body).lower()
        
        # Phishing keywords
        keywords = ['urgent', 'verify', 'account', 'suspended', 'click', 'immediately']
        found = [k for k in keywords if k in text]
        if found:
            score += len(found) * 10
            flags.append(f'PHISHING_KEYWORDS_{len(found)}')
        
        # Skrócone linki
        if 'bit.ly' in text or 'tinyurl' in text:
            score += 20
            flags.append('SHORTENED_URL')
        
        # Podejrzane domeny w sender
        bad_tlds = ['.tk', '.ml', '.ga']
        if any(tld in sender for tld in bad_tlds):
            score += 30
            flags.append('SUSPICIOUS_TLD')
        
        return {
            'sender': sender,
            'subject': subject,
            'date': msg.get('Date', ''),
            'score': min(score, 100),
            'flags': ','.join(flags)
        }
    
    def _save(self, result):
        """Zapisz do bazy"""
        c = self.db.cursor()
        c.execute('''INSERT INTO emails (sender, subject, date, score, flags)
                     VALUES (?, ?, ?, ?, ?)''',
                  (result['sender'], result['subject'], result['date'], 
                   result['score'], result['flags']))
        self.db.commit()
    
    def get_suspicious(self, threshold=50):
        """Pokaż podejrzane"""
        c = self.db.cursor()
        c.execute('SELECT * FROM emails WHERE score >= ? ORDER BY score DESC', (threshold,))
        return c.fetchall()
    
    def disconnect(self):
        """Rozłącz"""
        if self.conn:
            self.conn.logout()
        self.db.close()

# =====================================
# UŻYCIE - skopiuj do: scan_now.py
# =====================================

"""
#!/usr/bin/env python3
# scan_now.py - Uruchom skanowanie TERAZ

from core.simple_scanner import SimpleMailScanner

# GMAIL
scanner = SimpleMailScanner(
    server='imap.gmail.com',
    user='twoj_email@gmail.com',
    password='twoje_haslo_aplikacji'  # https://myaccount.google.com/apppasswords
)

if scanner.connect():
    print("✅ Połączono!")
    print("\\nSkanowanie ostatnich 10 wiadomości...\\n")
    
    results = scanner.scan_inbox(limit=10)
    
    print("\\n" + "=" * 60)
    print(f"Przeskanowano: {len(results)} wiadomości")
    
    suspicious = scanner.get_suspicious(threshold=50)
    print(f"Podejrzane (>=50): {len(suspicious)}")
    
    if suspicious:
        print("\\n🔴 TOP ZAGROŻENIA:")
        for row in suspicious[:5]:
            print(f"  Score {row[4]}: {row[2][:50]}")
    
    scanner.disconnect()
else:
    print("❌ Nie można połączyć")
"""
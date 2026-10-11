import sqlite3
import json
import os
import logging
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class MailHunterDB:
    def __init__(self, db_path=None):
        if db_path:
            self.db_path = db_path
        else:
            self.db_path = os.path.join(PROJECT_ROOT, 'data', 'mailhunter.db')
        
        self.is_memory = (self.db_path == ":memory:")
        self.conn = None
        
        if not self.is_memory:
            db_dir = os.path.dirname(self.db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
        self._init_database()
    
    def _get_conn(self):
        if self.is_memory:
            if self.conn is None:
                self.conn = sqlite3.connect(":memory:")
            return self.conn
        return sqlite3.connect(self.db_path)
    
    def _close_conn(self, conn):
        if not self.is_memory:
            conn.close()
    
    def _init_database(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE,
                account TEXT,
                folder TEXT,
                sender TEXT,
                recipient TEXT,
                subject TEXT,
                date TEXT,
                body_text TEXT,
                body_html TEXT,
                headers TEXT,
                scan_date TEXT,
                suspicious_score INTEGER,
                flags TEXT,
                status TEXT DEFAULT 'unprocessed'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER,
                filename TEXT,
                content_type TEXT,
                size INTEGER,
                suspicious BOOLEAN,
                hash TEXT,
                scan_result TEXT,
                FOREIGN KEY (email_id) REFERENCES emails(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER,
                url TEXT,
                display_text TEXT,
                suspicious BOOLEAN,
                virustotal_result TEXT,
                scan_date TEXT,
                FOREIGN KEY (email_id) REFERENCES emails(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER,
                ip_address TEXT,
                reputation_score INTEGER,
                abuse_reports INTEGER,
                country TEXT,
                isp TEXT,
                scan_date TEXT,
                FOREIGN KEY (email_id) REFERENCES emails(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                value TEXT UNIQUE,
                added_date TEXT,
                notes TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                value TEXT UNIQUE,
                added_date TEXT,
                reason TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_date TEXT,
                account TEXT,
                folder TEXT,
                emails_scanned INTEGER,
                suspicious_found INTEGER,
                scan_duration REAL,
                status TEXT
            )
        ''')
        
        conn.commit()
        if not self.is_memory:
            conn.close()
        self.logger.info("Baza danych zainicjalizowana")
    
    def insert_email(self, parsed_email, account, folder):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        try:
            headers = parsed_email['headers']
            body = parsed_email['body']
            analysis = parsed_email['analysis']
            
            cursor.execute('''
                INSERT INTO emails (
                    message_id, account, folder, sender, recipient, subject,
                    date, body_text, body_html, headers, scan_date,
                    suspicious_score, flags, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                headers.get('Message-ID', ''),
                account,
                folder,
                headers.get('From', ''),
                headers.get('To', ''),
                headers.get('Subject', ''),
                headers.get('Date', ''),
                body.get('text', ''),
                body.get('html', ''),
                json.dumps(headers),
                analysis['timestamp'],
                analysis['suspicious_score'],
                json.dumps(analysis['flags']),
                'scanned'
            ))
            
            email_id = cursor.lastrowid
            
            for attachment in parsed_email.get('attachments', []):
                cursor.execute('''
                    INSERT INTO attachments (
                        email_id, filename, content_type, size, suspicious
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    email_id,
                    attachment['filename'],
                    attachment['content_type'],
                    attachment['size'],
                    attachment['suspicious']
                ))
            
            for link in parsed_email.get('links', []):
                cursor.execute('''
                    INSERT INTO links (
                        email_id, url, display_text, suspicious, scan_date
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    email_id,
                    link['url'],
                    link.get('text', ''),
                    link.get('suspicious', False),
                    datetime.now().isoformat()
                ))
            
            conn.commit()
            self.logger.info(f"Zapisano wiadomość ID: {email_id}")
            return email_id
            
        except sqlite3.IntegrityError:
            self.logger.warning(f"Wiadomość już istnieje w bazie")
            return None
        except Exception as e:
            self.logger.error(f"Błąd zapisu do bazy: {str(e)}")
            conn.rollback()
            return None
        finally:
            self._close_conn(conn)
    
    def get_suspicious_emails(self, threshold=50):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, sender, subject, suspicious_score, scan_date, flags
            FROM emails
            WHERE suspicious_score >= ?
            ORDER BY suspicious_score DESC
        ''', (threshold,))
        
        results = cursor.fetchall()
        self._close_conn(conn)
        return results
    
    def update_email_status(self, email_id, status):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('UPDATE emails SET status = ? WHERE id = ?', (status, email_id))
        conn.commit()
        self._close_conn(conn)
    
    def add_to_whitelist(self, item_type, value, notes=''):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO whitelist (type, value, added_date, notes)
                VALUES (?, ?, ?, ?)
            ''', (item_type, value, datetime.now().isoformat(), notes))
            conn.commit()
            self.logger.info(f"Dodano do białej listy: {value}")
            return True
        except sqlite3.IntegrityError:
            self.logger.warning(f"Wpis już istnieje w białej liście: {value}")
            return False
        finally:
            self._close_conn(conn)
    
    def add_to_blacklist(self, item_type, value, reason=''):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO blacklist (type, value, added_date, reason)
                VALUES (?, ?, ?, ?)
            ''', (item_type, value, datetime.now().isoformat(), reason))
            conn.commit()
            self.logger.info(f"Dodano do czarnej listy: {value}")
            return True
        except sqlite3.IntegrityError:
            self.logger.warning(f"Wpis już istnieje w czarnej liście: {value}")
            return False
        finally:
            self._close_conn(conn)
    
    def is_whitelisted(self, item_type, value):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM whitelist WHERE type = ? AND value = ?', (item_type, value))
        result = cursor.fetchone()[0] > 0
        self._close_conn(conn)
        return result
    
    def is_blacklisted(self, item_type, value):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM blacklist WHERE type = ? AND value = ?', (item_type, value))
        result = cursor.fetchone()[0] > 0
        self._close_conn(conn)
        return result
    
    def log_scan(self, account, folder, emails_scanned, suspicious_found, duration):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_logs (
                scan_date, account, folder, emails_scanned,
                suspicious_found, scan_duration, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            account,
            folder,
            emails_scanned,
            suspicious_found,
            duration,
            'completed'
        ))
        
        conn.commit()
        self._close_conn(conn)
    
    def get_statistics(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        stats = {}
        
        cursor.execute('SELECT COUNT(*) FROM emails')
        stats['total_emails'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM emails WHERE suspicious_score >= 50')
        stats['suspicious_emails'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM emails WHERE suspicious_score >= 80')
        stats['dangerous_emails'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM attachments')
        stats['total_attachments'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM attachments WHERE suspicious = 1')
        stats['suspicious_attachments'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM links')
        stats['total_links'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM whitelist')
        stats['whitelist_entries'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM blacklist')
        stats['blacklist_entries'] = cursor.fetchone()[0]
        
        self._close_conn(conn)
        return stats

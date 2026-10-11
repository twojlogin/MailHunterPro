"""Attachment Sandbox - Bezpieczne otwieranie załączników"""
import os
import tempfile
import logging
import hashlib

class AttachmentSandbox:
    """Sandboxing podejrzanych załączników"""
    
    # Niebezpieczne rozszerzenia
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.msi', '.scr', '.pif',
        '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
        '.ps1', '.ps2', '.psc1', '.psc2',
        '.reg', '.rgs', '.sct', '.shb', '.shs',
        '.lnk', '.inf', '.reg', '.doc', '.docm', '.xlsm'
    }
    
    def __init__(self, quarantine_dir=None):
        self.logger = logging.getLogger(__name__)
        self.quarantine_dir = quarantine_dir or tempfile.mkdtemp(prefix='mailhunter_quarantine_')
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
    def analyze_attachment(self, filename, content):
        """Analizuje załącznik pod kątem bezpieczeństwa"""
        result = {
            'filename': filename,
            'safe': True,
            'risk_level': 'LOW',
            'flags': [],
            'quarantined': False
        }
        
        # Sprawdź rozszerzenie
        _, ext = os.path.splitext(filename.lower())
        if ext in self.DANGEROUS_EXTENSIONS:
            result['safe'] = False
            result['risk_level'] = 'HIGH'
            result['flags'].append(f'DANGEROUS_EXTENSION: {ext}')
            
        # Sprawdź magic bytes
        if content[:4] == b'MZ\x90\x00':  # PE executable
            result['safe'] = False
            result['risk_level'] = 'CRITICAL'
            result['flags'].append('EXECUTABLE_FILE')
            
        # Sprawdź rozmiar
        if len(content) > 10 * 1024 * 1024:  # > 10MB
            result['flags'].append('LARGE_FILE')
            
        # Hash dla trackingu
        result['md5'] = hashlib.md5(content).hexdigest()
        result['sha256'] = hashlib.sha256(content).hexdigest()
        
        # Kwarantanna jeśli niebezpieczny
        if not result['safe']:
            self._quarantine(filename, content)
            result['quarantined'] = True
            
        return result
    
    def _quarantine(self, filename, content):
        """Przenosi plik do kwarantanny"""
        try:
            safe_name = hashlib.md5(filename.encode()).hexdigest()
            path = os.path.join(self.quarantine_dir, safe_name)
            with open(path, 'wb') as f:
                f.write(content)
            self.logger.warning(f"Plik skierowany do kwarantanny: {filename}")
        except Exception as e:
            self.logger.error(f"Błąd kwarantanny: {e}")

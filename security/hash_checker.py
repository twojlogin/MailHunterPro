"""Hash Checker - Weryfikacja integralności plików"""
import hashlib
import logging

class HashChecker:
    """Sprawdzanie hashów plików"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.known_hashes = {}  # {hash: filename}
        
    def calculate_hash(self, content, algorithm='sha256'):
        """Oblicza hash"""
        if algorithm == 'md5':
            return hashlib.md5(content).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(content).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(content).hexdigest()
        else:
            raise ValueError(f"Nieobsługiwany algorytm: {algorithm}")
    
    def check_known_malware(self, content):
        """Sprawdza czy hash jest znany jako malware"""
        file_hash = self.calculate_hash(content)
        
        # Tu można dodać bazęhashy malware
        # Na razie tylko logujemy
        if file_hash in self.known_hashes:
            self.logger.warning(f"Znany hash malware: {file_hash}")
            return True, self.known_hashes[file_hash]
        
        return False, None
    
    def add_known_hash(self, hash_value, description=""):
        """Dodaje hash do bazy"""
        self.known_hashes[hash_value] = description
        
    def verify_integrity(self, content, expected_hash):
        """Weryfikuje integralność"""
        actual_hash = self.calculate_hash(content)
        return actual_hash == expected_hash

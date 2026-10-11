"""Tor Anonymizer - Ghost Mode dla MailHunterPro"""
import socket
import socks
import logging

class TorAnonymizer:
    """Anonimizacja połączeń przez Tor"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.connected = False
        self.socks_port = 9050  # Default Tor SOCKS port
        
    def connect(self, socks_port=9050):
        """Łączy się z Tor"""
        try:
            self.socks_port = socks_port
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", socks_port)
            socket.socket = socks.socksocket
            self.connected = True
            self.logger.info(f"Połączono z Tor na porcie {socks_port}")
            return True
        except Exception as e:
            self.logger.error(f"Błąd połączenia z Tor: {e}")
            return False
    
    def disconnect(self):
        """Rozłącza Tor"""
        # Przywraca domyślny socket
        import socket as default_socket
        socket.socket = default_socket.socket
        self.connected = False
        self.logger.info("Rozłączono z Tor")
        
    def check_ip(self):
        """Sprawdza aktualne IP (przez Tor)"""
        if not self.connected:
            return None
            
        try:
            import requests
            response = requests.get('https://api.ipify.org?format=json', timeout=10)
            return response.json()['ip']
        except:
            return None
            
    def is_available(self):
        """Sprawdza czy Tor jest dostępny"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", self.socks_port))
            s.close()
            return True
        except:
            return False

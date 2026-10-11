import imaplib
import email
import ssl
import logging
from datetime import datetime, timedelta

from core.config import PROVIDERS

# ProtonMail wymaga lokalnego mostu (Bridge) na tym porcie. Reszta to zwykły
# IMAP po TLS. Port 993 dla wszystkich poza Protonem.
PROTON_BRIDGE_PORT = 1143


class EmailClient:
    def __init__(self, config):
        self.config = config
        self.connection = None
        self.logger = logging.getLogger(__name__)
        self.imap_servers = {
            nazwa: (host, PROTON_BRIDGE_PORT if nazwa == 'proton' else 993)
            for nazwa, host in PROVIDERS.items()
        }

    def connect(self, account, username=None, password=None):
        """Łączy się z serwerem IMAP.

        `account` to nazwa konta albo providera: 'gmail', 'gmail_praca',
        'outlook_firma'. Nazwy z sufiksem to wiele kont jednego providera —
        serwer bierzemy z providera, dane logowania z konta.
        """
        try:
            provider = self.config.account_provider(account) or account
            if not username or not password:
                username, password = self.config.get_account_credentials(account)
            if not username or not password:
                username, password = self.config.get_email_credentials(provider)

            if not username or not password:
                raise ValueError(f"Brak danych logowania dla konta: {account}")

            server, port = self.imap_servers.get(provider, ('', 993))
            if not server:
                raise ValueError(
                    f"Nieobsługiwany provider: {provider}. "
                    f"Dostępne: {', '.join(sorted(self.imap_servers))}"
                )

            # Tworzenie bezpiecznego połączenia
            context = ssl.create_default_context()
            self.connection = imaplib.IMAP4_SSL(server, port, ssl_context=context)

            # Logowanie
            self.connection.login(username, password)
            self.logger.info("Połączono z %s (%s) jako %s", account, provider, username)

            return True

        except Exception as e:
            self.logger.error(f"Błąd połączenia z {account}: {str(e)}")
            return False
    
    def select_folder(self, folder_name="INBOX"):
        """Wybiera folder do skanowania"""
        if not self.connection:
            raise ConnectionError("Brak połączenia z serwerem")
        
        try:
            status, count = self.connection.select(folder_name)
            if status == 'OK':
                message_count = int(count[0])
                self.logger.info(f"Wybrano folder {folder_name}, liczba wiadomości: {message_count}")
                return message_count
            else:
                raise Exception(f"Nie można wybrać folderu {folder_name}")
        except Exception as e:
            self.logger.error(f"Błąd wyboru folderu: {str(e)}")
            raise
    
    def search_messages(self, criteria="ALL", date_from=None, date_to=None):
        """Wyszukuje wiadomości według kryteriów"""
        if not self.connection:
            raise ConnectionError("Brak połączenia z serwerem")
        
        search_criteria = [criteria]
        
        # Dodanie kryteriów daty
        if date_from:
            search_criteria.append(f'SINCE "{date_from.strftime("%d-%b-%Y")}"')
        if date_to:
            search_criteria.append(f'BEFORE "{date_to.strftime("%d-%b-%Y")}"')
        
        search_string = " ".join(search_criteria)
        
        try:
            status, messages = self.connection.search(None, search_string)
            if status == 'OK':
                message_nums = messages[0].split()
                self.logger.info(f"Znaleziono {len(message_nums)} wiadomości")
                return [int(num) for num in message_nums]
            else:
                return []
        except Exception as e:
            self.logger.error(f"Błąd wyszukiwania: {str(e)}")
            return []
    
    def fetch_message(self, message_num):
        """Pobiera pojedynczą wiadomość"""
        if not self.connection:
            raise ConnectionError("Brak połączenia z serwerem")
        
        try:
            status, data = self.connection.fetch(str(message_num), '(RFC822)')
            if status == 'OK':
                raw_email = data[0][1]
                email_message = email.message_from_bytes(raw_email)
                return email_message
            else:
                return None
        except Exception as e:
            self.logger.error(f"Błąd pobierania wiadomości {message_num}: {str(e)}")
            return None
    
    def get_folder_list(self):
        """Pobiera listę dostępnych folderów"""
        if not self.connection:
            raise ConnectionError("Brak połączenia z serwerem")
        
        try:
            status, folders = self.connection.list()
            if status == 'OK':
                folder_list = []
                for folder in folders:
                    # Parsowanie nazwy folderu
                    folder_name = folder.decode().split('"')[-2]
                    folder_list.append(folder_name)
                return folder_list
            else:
                return []
        except Exception as e:
            self.logger.error(f"Błąd pobierania listy folderów: {str(e)}")
            return []
    
    def disconnect(self):
        """Rozłącza się z serwerem"""
        if self.connection:
            try:
                self.connection.close()
                self.connection.logout()
                self.logger.info("Rozłączono z serwerem")
            except:
                pass
            finally:
                self.connection = None

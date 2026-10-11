# mailhunter.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import logging
from datetime import datetime, timedelta
import sys
import os

# Import modułów MailHunter
from core.config import MailHunterConfig
from core.email_client import EmailClient
from core.parser import EmailParser
from core.database import MailHunterDB
from core.security_analyzer import SecurityAnalyzer

class MailHunterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MailHunter - Advanced Email Security Scanner")
        self.root.geometry("1000x700")
        
        # Definiuje absolutny korzeń projektu
        self.project_root = os.path.dirname(os.path.abspath(__file__))

        # Inicjalizacja komponentów
        self.setup_logging()
        self.config = MailHunterConfig()
        self.database = MailHunterDB()
        self.email_client = EmailClient(self.config)
        self.parser = EmailParser()
        self.security_analyzer = SecurityAnalyzer(self.config, self.database)
        
        # Zmienne GUI
        self.scanning = False
        self.scan_thread = None
        
        # Tworzenie interfejsu
        self.create_gui()
        
        # Ładowanie statystyk
        self.update_statistics()
    
    def setup_logging(self):
        """Konfiguruje system logowania"""
        log_dir = os.path.join(self.project_root, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_filename = os.path.join(log_dir, f"mailhunter_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("MailHunter uruchomiony")
    
    def create_gui(self):
        """Tworzy interfejs użytkownika"""
        # Menu górne
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Plik", menu=file_menu)
        file_menu.add_command(label="Ustawienia", command=self.show_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Wyjście", command=self.root.quit)
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Narzędzia", menu=tools_menu)
        tools_menu.add_command(label="Zarządzaj listami", command=self.manage_lists)
        tools_menu.add_command(label="Eksport danych", command=self.export_data)
        tools_menu.add_command(label="Oczyszczanie skrzynki", command=self.cleanup_mailbox)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Pomoc", menu=help_menu)
        help_menu.add_command(label="O programie", command=self.show_about)
        
        # Panel główny z zakładkami
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Zakładka: Skanowanie
        self.create_scan_tab()
        
        # Zakładka: Wyniki
        self.create_results_tab()
        
        # Zakładka: Statystyki
        self.create_stats_tab()
        
        # Panel statusu na dole
        self.create_status_panel()
    
    def create_scan_tab(self):
        """Tworzy zakładkę skanowania"""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="Skanowanie")
        
        # Sekcja konfiguracji skanowania
        config_frame = ttk.LabelFrame(scan_frame, text="Konfiguracja skanowania", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Wybór konta
        ttk.Label(config_frame, text="Konto e-mail:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.account_var = tk.StringVar(value="gmail")
        account_combo = ttk.Combobox(config_frame, textvariable=self.account_var, 
                                     values=["gmail", "outlook", "proton"], state="readonly", width=30)
        account_combo.grid(row=0, column=1, sticky=tk.W, pady=5, padx=10)
        
        # Wybór folderu
        ttk.Label(config_frame, text="Folder:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.folder_var = tk.StringVar(value="INBOX")
        self.folder_combo = ttk.Combobox(config_frame, textvariable=self.folder_var,
                                    values=["INBOX", "SPAM", "Sent", "Trash"], width=30)
        self.folder_combo.grid(row=1, column=1, sticky=tk.W, pady=5, padx=10)
        
        ttk.Button(config_frame, text="Odśwież listę folderów", 
                  command=self.refresh_folders).grid(row=1, column=2, padx=5)
        
        # Zakres dat
        ttk.Label(config_frame, text="Zakres dat:").grid(row=2, column=0, sticky=tk.W, pady=5)
        
        date_frame = ttk.Frame(config_frame)
        date_frame.grid(row=2, column=1, sticky=tk.W, pady=5, padx=10)
        
        self.date_range_var = tk.StringVar(value="last_7_days")
        ttk.Radiobutton(date_frame, text="Ostatnie 7 dni", variable=self.date_range_var,
                       value="last_7_days").pack(side=tk.LEFT)
        ttk.Radiobutton(date_frame, text="Ostatnie 30 dni", variable=self.date_range_var,
                       value="last_30_days").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(date_frame, text="Wszystkie", variable=self.date_range_var,
                       value="all").pack(side=tk.LEFT)
        
        # Poziom skanowania
        ttk.Label(config_frame, text="Poziom skanowania:").grid(row=3, column=0, sticky=tk.W, pady=5)
        
        level_frame = ttk.Frame(config_frame)
        level_frame.grid(row=3, column=1, sticky=tk.W, pady=5, padx=10)
        
        self.scan_level_var = tk.StringVar(value="normal")
        ttk.Radiobutton(level_frame, text="Normalny", variable=self.scan_level_var,
                       value="normal").pack(side=tk.LEFT)
        ttk.Radiobutton(level_frame, text="Zaawansowany", variable=self.scan_level_var,
                       value="advanced").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(level_frame, text="Głęboki (z API)", variable=self.scan_level_var,
                       value="deep").pack(side=tk.LEFT)
        
        # Opcje dodatkowe
        options_frame = ttk.LabelFrame(scan_frame, text="Opcje dodatkowe", padding=10)
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.auto_quarantine_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Automatyczna kwarantanna (score >= 90)",
                       variable=self.auto_quarantine_var).pack(anchor=tk.W)
        
        self.scan_attachments_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Skanuj załączniki",
                       variable=self.scan_attachments_var).pack(anchor=tk.W)
        
        self.check_links_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Sprawdzaj linki (VirusTotal, jeśli włączony)",
                       variable=self.check_links_var).pack(anchor=tk.W)
        
        # Przyciski akcji
        action_frame = ttk.Frame(scan_frame)
        action_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.scan_button = ttk.Button(action_frame, text="🔍 Rozpocznij skanowanie",
                                      command=self.start_scan, style="Accent.TButton")
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(action_frame, text="⏹ Stop",
                                      command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        progress_frame = ttk.LabelFrame(scan_frame, text="Postęp", padding=10)
        progress_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var,
                                           maximum=100, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.progress_label = ttk.Label(progress_frame, text="Gotowy do skanowania")
        self.progress_label.pack(anchor=tk.W)
        
        # Konsola logów
        log_frame = ttk.LabelFrame(scan_frame, text="Logi skanowania", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, state=tk.DISABLED,
                                                   wrap=tk.WORD, font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    def create_results_tab(self):
        """Tworzy zakładkę wyników"""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Wyniki")
        
        # Filtry
        filter_frame = ttk.LabelFrame(results_frame, text="Filtry", padding=10)
        filter_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(filter_frame, text="Pokaż:").pack(side=tk.LEFT)
        
        self.filter_var = tk.StringVar(value="all")
        ttk.Radiobutton(filter_frame, text="Wszystkie", variable=self.filter_var,
                       value="all", command=self.refresh_results).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(filter_frame, text="Podejrzane (50+)", variable=self.filter_var,
                       value="suspicious", command=self.refresh_results).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(filter_frame, text="Niebezpieczne (80+)", variable=self.filter_var,
                       value="dangerous", command=self.refresh_results).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(filter_frame, text="Odśwież", 
                  command=self.refresh_results).pack(side=tk.RIGHT, padx=5)
        
        # Tabela wyników
        table_frame = ttk.Frame(results_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical")
        hsb = ttk.Scrollbar(table_frame, orient="horizontal")
        
        # Treeview
        self.results_tree = ttk.Treeview(table_frame, 
                                         columns=("id", "date", "sender", "subject", "score", "flags"),
                                         show="headings",
                                         yscrollcommand=vsb.set,
                                         xscrollcommand=hsb.set)
        
        vsb.config(command=self.results_tree.yview)
        hsb.config(command=self.results_tree.xview)
        
        # Definiowanie kolumn
        self.results_tree.heading("id", text="ID")
        self.results_tree.heading("date", text="Data")
        self.results_tree.heading("sender", text="Nadawca")
        self.results_tree.heading("subject", text="Temat")
        self.results_tree.heading("score", text="Score")
        self.results_tree.heading("flags", text="Flagi")
        
        self.results_tree.column("id", width=50)
        self.results_tree.column("date", width=150)
        self.results_tree.column("sender", width=200)
        self.results_tree.column("subject", width=300)
        self.results_tree.column("score", width=70)
        self.results_tree.column("flags", width=200)
        
        # Kolorowanie wierszy według score
        self.results_tree.tag_configure('safe', background='#d4edda')
        self.results_tree.tag_configure('suspicious', background='#fff3cd')
        self.results_tree.tag_configure('dangerous', background='#f8d7da')
        
        # Pakowanie
        self.results_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Bind double-click
        self.results_tree.bind('<Double-1>', self.show_email_details)
        
        # Przyciski akcji
        button_frame = ttk.Frame(results_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Szczegóły",
                  command=self.show_email_details).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Eksportuj EML",
                  command=self.export_eml).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Dodaj do białej listy",
                  command=self.add_to_whitelist).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Dodaj do czarnej listy",
                  command=self.add_to_blacklist).pack(side=tk.LEFT, padx=5)
    
    def create_stats_tab(self):
        """Tworzy zakładkę statystyk"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Statystyki")
        
        # Statystyki ogólne
        general_frame = ttk.LabelFrame(stats_frame, text="Statystyki ogólne", padding=20)
        general_frame.pack(fill=tk.BOTH, padx=10, pady=10)
        
        # Grid dla statystyk
        stats_grid = ttk.Frame(general_frame)
        stats_grid.pack()
        
        self.stats_labels = {}
        stats_items = [
            ("total_emails", "Przeskanowane wiadomości:"),
            ("suspicious_emails", "Podejrzane wiadomości:"),
            ("dangerous_emails", "Niebezpieczne wiadomości:"),
            ("total_attachments", "Załączniki:"),
            ("suspicious_attachments", "Podejrzane załączniki:"),
            ("total_links", "Linki:"),
            ("whitelist_entries", "Biała lista:"),
            ("blacklist_entries", "Czarna lista:")
        ]
        
        for idx, (key, label) in enumerate(stats_items):
            ttk.Label(stats_grid, text=label, font=("Arial", 10)).grid(
                row=idx, column=0, sticky=tk.W, pady=5, padx=5)
            value_label = ttk.Label(stats_grid, text="0", font=("Arial", 10, "bold"))
            value_label.grid(row=idx, column=1, sticky=tk.W, pady=5, padx=20)
            self.stats_labels[key] = value_label
        
        # Przycisk odświeżania
        ttk.Button(stats_frame, text="Odśwież statystyki",
                  command=self.update_statistics).pack(pady=10)
        
        # Wykresy (opcjonalnie - wymaga matplotlib)
        charts_frame = ttk.LabelFrame(stats_frame, text="Wykresy", padding=10)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(charts_frame, text="Wykresy będą dostępne w przyszłej wersji",
                 font=("Arial", 10, "italic")).pack(pady=20)
    
    def create_status_panel(self):
        """Tworzy panel statusu"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(status_frame, text="Gotowy", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2, pady=2)
        
        self.connection_label = ttk.Label(status_frame, text="⚫ Rozłączony", 
                                         relief=tk.SUNKEN, width=20)
        self.connection_label.pack(side=tk.RIGHT, padx=2, pady=2)
    
    def log_message(self, message, level="INFO"):
        """Dodaje wiadomość do konsoli logów"""
        self.log_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {level}: {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def refresh_folders(self):
        """Odświeża listę folderów"""
        account = self.account_var.get()
        self.log_message(f"Pobieranie listy folderów dla {account}...")
        
        def fetch_folders():
            try:
                if self.email_client.connect(account):
                    self.connection_label.config(text="🟢 Połączony")
                    folders = self.email_client.get_folder_list()
                    
                    # Aktualizuj combo box w głównym wątku
                    self.root.after(0, lambda: self._update_folder_combo(folders))
                    self.log_message(f"Znaleziono {len(folders)} folderów")
                    
                    self.email_client.disconnect()
                    self.connection_label.config(text="⚫ Rozłączony")
                else:
                    self.log_message("Błąd połączenia", "ERROR")
            except Exception as e:
                self.log_message(f"Błąd: {str(e)}", "ERROR")
        
        threading.Thread(target=fetch_folders, daemon=True).start()
    
    def _update_folder_combo(self, folders):
        """Aktualizuje listę folderów w combo box"""
        folder_combo = None
        for widget in self.root.winfo_children():
            # Znajdź combo box (uproszczone)
            pass
        # TODO: Implementacja aktualizacji combo box
    
    def start_scan(self):
        """Rozpoczyna skanowanie"""
        if self.scanning:
            messagebox.showwarning("Uwaga", "Skanowanie już trwa!")
            return
        
        account = self.account_var.get()
        folder = self.folder_var.get()
        date_range = self.date_range_var.get()
        
        # Oblicz zakres dat
        date_from = None
        date_to = None
        
        if date_range == "last_7_days":
            date_from = datetime.now() - timedelta(days=7)
        elif date_range == "last_30_days":
            date_from = datetime.now() - timedelta(days=30)
        
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Uruchom skanowanie w osobnym wątku
        self.scan_thread = threading.Thread(
            target=self._perform_scan,
            args=(account, folder, date_from, date_to),
            daemon=True
        )
        self.scan_thread.start()
    
    def _perform_scan(self, account, folder, date_from, date_to):
        """Wykonuje skanowanie w osobnym wątku"""
        start_time = datetime.now()
        scanned_count = 0
        suspicious_count = 0
        
        try:
            self.log_message(f"Rozpoczęcie skanowania: {account}/{folder}")
            self.status_label.config(text=f"Łączenie z {account}...")
            
            # Połącz z serwerem
            if not self.email_client.connect(account):
                self.log_message("Nie można połączyć z serwerem", "ERROR")
                return
            
            self.connection_label.config(text="🟢 Połączony")
            
            # Wybierz folder
            message_count = self.email_client.select_folder(folder)
            self.log_message(f"Znaleziono {message_count} wiadomości w folderze")
            
            # Wyszukaj wiadomości
            message_nums = self.email_client.search_messages(
                criteria="ALL",
                date_from=date_from,
                date_to=date_to
            )
            
            total_messages = len(message_nums)
            self.log_message(f"Do przeskanowania: {total_messages} wiadomości")
            
            # Skanuj każdą wiadomość
            for idx, msg_num in enumerate(message_nums):
                if not self.scanning:
                    self.log_message("Skanowanie przerwane przez użytkownika", "WARNING")
                    break
                
                try:
                    # Pobierz wiadomość
                    email_message = self.email_client.fetch_message(msg_num)
                    if not email_message:
                        continue
                    
                    # Parsuj wiadomość
                    parsed_email = self.parser.parse_message(email_message)
                    if not parsed_email:
                        continue
                    
                    # Analiza bezpieczeństwa
                    analyzed_email = self.security_analyzer.analyze_email(parsed_email)
                    
                    # Zapisz do bazy
                    email_id = self.database.insert_email(analyzed_email, account, folder)
                    
                    # Aktualizuj liczniki
                    scanned_count += 1
                    if analyzed_email['analysis']['suspicious_score'] >= 50:
                        suspicious_count += 1
                    
                    # Aktualizuj progress
                    progress = (idx + 1) / total_messages * 100
                    self.root.after(0, lambda p=progress: self.progress_var.set(p))
                    
                    # Aktualizuj status
                    status_text = f"Skanowanie: {idx + 1}/{total_messages} | " \
                                f"Podejrzane: {suspicious_count}"
                    self.root.after(0, lambda t=status_text: self.status_label.config(text=t))
                    
                    # Log co 10 wiadomości
                    if (idx + 1) % 10 == 0:
                        self.log_message(f"Przeskanowano {idx + 1}/{total_messages}")
                    
                    # Auto-kwarantanna
                    if (self.auto_quarantine_var.get() and 
                        analyzed_email['analysis']['suspicious_score'] >= 90):
                        self.log_message(
                            f"KWARANTANNA: {analyzed_email['headers'].get('Subject', 'No subject')}",
                            "WARNING"
                        )
                        self.database.update_email_status(email_id, 'quarantined')
                
                except Exception as e:
                    self.log_message(f"Błąd przetwarzania wiadomości {msg_num}: {str(e)}", "ERROR")
                    continue
            
            # Rozłącz
            self.email_client.disconnect()
            self.connection_label.config(text="⚫ Rozłączony")
            
            # Podsumowanie
            duration = (datetime.now() - start_time).total_seconds()
            self.database.log_scan(account, folder, scanned_count, suspicious_count, duration)
            
            self.log_message("=" * 50)
            self.log_message(f"Skanowanie zakończone!")
            self.log_message(f"Przeskanowano: {scanned_count} wiadomości")
            self.log_message(f"Znaleziono podejrzanych: {suspicious_count}")
            self.log_message(f"Czas trwania: {duration:.2f}s")
            self.log_message("=" * 50)
            
            # Odśwież statystyki i wyniki
            self.root.after(0, self.update_statistics)
            self.root.after(0, self.refresh_results)
            
        except Exception as e:
            self.log_message(f"Błąd krytyczny: {str(e)}", "ERROR")
            self.logger.exception("Błąd podczas skanowania")
        
        finally:
            self.scanning = False
            self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.status_label.config(text="Gotowy"))
    
    def stop_scan(self):
        """Zatrzymuje skanowanie"""
        if self.scanning:
            self.scanning = False
            self.log_message("Zatrzymywanie skanowania...", "WARNING")
    
    def refresh_results(self):
        """Odświeża tabelę wyników"""
        # Wyczyść tabelę
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Pobierz dane według filtra
        filter_type = self.filter_var.get()
        
        if filter_type == "suspicious":
            threshold = 50
        elif filter_type == "dangerous":
            threshold = 80
        else:
            threshold = 0
        
        results = self.database.get_suspicious_emails(threshold)
        
        # Wypełnij tabelę
        for row in results:
            email_id, sender, subject, score, scan_date, flags = row
            
            # Określ tag (kolor)
            if score >= 80:
                tag = 'dangerous'
            elif score >= 50:
                tag = 'suspicious'
            else:
                tag = 'safe'
            
            # Formatuj flagi
            try:
                flags_list = eval(flags) if flags else []
                flags_str = ', '.join(flags_list[:3])  # Pierwsze 3 flagi
                if len(flags_list) > 3:
                    flags_str += f" +{len(flags_list)-3}"
            except:
                flags_str = "N/A"
            
            self.results_tree.insert('', 'end', values=(
                email_id,
                scan_date[:16] if scan_date else "N/A",
                sender[:40],
                subject[:50] if subject else "(brak tematu)",
                score,
                flags_str
            ), tags=(tag,))
        
        self.log_message(f"Załadowano {len(results)} wyników")
    
    def update_statistics(self):
        """Aktualizuje statystyki"""
        stats = self.database.get_statistics()
        
        for key, value in stats.items():
            if key in self.stats_labels:
                self.stats_labels[key].config(text=str(value))
    
    def show_email_details(self, event=None):
        """Pokazuje szczegóły wybranej wiadomości"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Wybierz wiadomość z listy")
            return
        
        # TODO: Implementacja okna szczegółów
        messagebox.showinfo("Szczegóły", "Funkcja w przygotowaniu")
    
    def export_eml(self):
        """Eksportuje wybraną wiadomość do EML"""
        # TODO: Implementacja eksportu EML
        messagebox.showinfo("Eksport", "Funkcja w przygotowaniu")
    
    def add_to_whitelist(self):
        """Dodaje nadawcę do białej listy"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Wybierz wiadomość z listy")
            return
        
        # TODO: Implementacja dodawania do białej listy
        messagebox.showinfo("Biała lista", "Funkcja w przygotowaniu")
    
    def add_to_blacklist(self):
        """Dodaje nadawcę do czarnej listy"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Wybierz wiadomość z listy")
            return
        
        # TODO: Implementacja dodawania do czarnej listy
        messagebox.showinfo("Czarna lista", "Funkcja w przygotowaniu")
    
    def show_settings(self):
        """Pokazuje okno ustawień"""
        # TODO: Implementacja okna ustawień
        messagebox.showinfo("Ustawienia", "Funkcja w przygotowaniu")
    
    def manage_lists(self):
        """Zarządzanie białą/czarną listą"""
        # TODO: Implementacja zarządzania listami
        messagebox.showinfo("Zarządzanie listami", "Funkcja w przygotowaniu")
    
    def export_data(self):
        """Eksport danych do CSV/JSON"""
        # TODO: Implementacja eksportu danych
        messagebox.showinfo("Eksport", "Funkcja w przygotowaniu")
    
    def cleanup_mailbox(self):
        """Narzędzie do czyszczenia skrzynki"""
        # TODO: Implementacja czyszczenia
        messagebox.showinfo("Oczyszczanie", "Funkcja w przygotowaniu")
    
    def show_about(self):
        """Pokazuje okno 'O programie'"""
        about_text = """MailHunter v1.0
        
Zaawansowane narzędzie do analizy bezpieczeństwa e-maili

Funkcje:
• Skanowanie kont IMAP (Gmail, Outlook, ProtonMail)
• Analiza nagłówków i detekcja spoofingu
• Wykrywanie phishingu i złośliwych linków
• Skanowanie załączników
• System punktacji zagrożeń
• Białe i czarne listy
• Automatyczna kwarantanna

Utworzono dla użytkowników, którzy dbają o cyberbezpieczeństwo.
        """
        messagebox.showinfo("O programie", about_text)

def main():
    """Główna funkcja aplikacji"""
    # Definiuje absolutny korzeń projektu
    project_root = os.path.dirname(os.path.abspath(__file__))

    # Tworzenie katalogów przy użyciu absolutnych ścieżek
    os.makedirs(os.path.join(project_root, 'data'), exist_ok=True)
    os.makedirs(os.path.join(project_root, 'data', 'quarantine'), exist_ok=True)
    os.makedirs(os.path.join(project_root, 'data', 'export'), exist_ok=True)
    os.makedirs(os.path.join(project_root, 'logs'), exist_ok=True)
    
    # Uruchomienie GUI
    root = tk.Tk()
    app = MailHunterGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
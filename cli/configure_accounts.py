#!/usr/bin/env python3
"""Dodaj konta e-mail do MailHunterPro.

Nie wpisuj hasła głównego. Gmail i Outlook wymagają hasła aplikacji:
  Gmail:    https://myaccount.google.com/apppasswords
  Outlook:  konto → bezpieczeństwo → hasła aplikacji
  Yahoo:    wymaga włączonego 2FA i osobnego hasła aplikacji
  Proton:   wymaga ProtonMail Bridge działającego lokalnie (port 1143)

Interaktywne. Hasła szyfrowane kluczem z mailhunter.key i nigdzie poza
config.ini nie trafiają. Pliki są w .gitignore — nie wklejaj ich do repo.

    python configure_accounts.py
"""

import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import PROVIDERS, MailHunterConfig

# Providerzy, gdzie hasło aplikacji jest obowiązkowe — inaczej konto
# zablokuje po kilku nieudanych próbach logowania.
HASLO_APLIKACJI = {
    'gmail': 'https://myaccount.google.com/apppasswords',
    'outlook': 'konto → bezpieczeństwo → hasła aplikacji',
    'yahoo': 'konto → bezpieczeństwo → wygeneruj hasło aplikacji',
    'proton': 'wymaga ProtonMail Bridge na porcie 1143',
}

# Gdzie brać dane, gdy ktoś nie pamięta serwera IMAP.
GDZIE_SZUKAC = 'docs: https://www.google.com/search?q=imap+server+{provider}'


def pokaz_stan(config):
    konta = config.list_accounts()
    print()
    if not konta:
        print("  Brak zapisanych kont.")
        return
    print(f"  Zapisane konta ({len(konta)}):")
    for nazwa in konta:
        provider = config.account_provider(nazwa) or '?'
        login, _ = config.get_account_credentials(nazwa)
        print(f"    {nazwa:24} {provider:10} {login or '(brak loginu)'}")
    print()
    print("  Usunąć konto:  python configure_accounts.py --usun NAZWA")
    print("  Np.           python configure_accounts.py --usun gmail_praca")


def dodaj_konto(config, provider, nazwa=None):
    """Dodaje jedno konto. Wraca nazwę konta albo None przy odstąpieniu."""
    label = f"{provider}" + (f" / {nazwa}" if nazwa else "")

    if provider in HASLO_APLIKACJI:
        print(f"\n  UWAGA: {provider} wymaga HASŁA APLIKACJI, nie głównego.")
        print(f"  {HASLO_APLIKACJI[provider]}")
        print(f"  Serwer: {PROVIDERS[provider]}:993"
              + ("" if provider != 'proton' else " (przez Bridge)"))

    login = input(f"\n  Login dla {label} (Enter = pomiń): ").strip()
    if not login:
        return None

    haslo = getpass.getpass(f"  Hasło aplikacji dla {login}: ")
    if not haslo:
        print("  Bez hasła nie da się połączyć. Pomijam.")
        return None

    klucz = f"{provider}_{nazwa}" if nazwa else provider
    config.set_email_credentials(klucz, login, haslo)
    print(f"  Zapisano konto: {klucz}")
    return klucz


def glowny():
    config = MailHunterConfig()

    if "--usun" in sys.argv:
        i = sys.argv.index("--usun")
        if i + 1 >= len(sys.argv):
            print("Podaj nazwę konta, np. --usun gmail_praca")
            return 1
        nazwa = sys.argv[i + 1]
        if config.remove_email_credentials(nazwa):
            print(f"Usunięto konto: {nazwa}")
        else:
            print(f"Nie ma konta: {nazwa}")
            pokaz_stan(config)
        return 0

    print("=" * 62)
    print(" MailHunterPro — konta e-mail")
    print("=" * 62)

    print("\n  Obsługiwane serwery IMAP:")
    for nazwa, host in sorted(PROVIDERS.items()):
        port = 1143 if nazwa == 'proton' else 993
        print(f"    {nazwa:12} {host}:{port}")
    print(f"\n  Aliasy outlook.com/hotmail.com/live.com → outlook")
    print(f"  Wiele kont na jednym providerze: podaj nazwę po podkreśleniu")
    print(f"  (gmail_praca, gmail_personal, outlook_firma)")

    pokaz_stan(config)

    print("\n" + "=" * 62)
    print(" Dodawanie kont")
    print("=" * 62)

    dodane = []
    while True:
        print("\n  Provider (Enter = koniec): ", end="")
        wybor = input().strip().lower()
        if not wybor:
            break

        if wybor not in PROVIDERS:
            print(f"  Nieznany provider: {wybor}")
            print(f"  Dostępne: {', '.join(sorted(PROVIDERS))}")
            continue

        nazwa = ""
        if wybor in ("gmail", "outlook", "proton", "yahoo", "icloud"):
            odp = input(f"  Nazwa konta na {wybor} (Enter = domyślna): ").strip()
            nazwa = odp.replace("_", "-").strip() if odp else ""

        if dodaj_konto(config, wybor, nazwa):
            dodane.append(f"{wybor}_{nazwa}" if nazwa else wybor)

    print("\n" + "=" * 62)
    if dodane:
        print(f" Dodano {len(dodane)} kont: {', '.join(dodane)}")
    else:
        print(" Nic nie dodano.")
    pokaz_stan(config)
    print("\n  Uruchom skan:  python mailhunter_cli.py scan --account NAZWA")
    print("  Web UI:        python web/server.py")
    return 0


if __name__ == "__main__":
    sys.exit(glowny())

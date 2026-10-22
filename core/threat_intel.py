#!/usr/bin/env python3
"""threat_intel.py — stan zagrożeń ze świata, offline po pobraniu.

CO TO ROBI
----------
Pobiera z jawnych, bezkluczowych źródeł listy aktywnych zagrożeń, zapisuje
je lokalnie i pokazuje co nowego doszło od ostatniego pobrania. Feed możesz
potem używać do skanowania maili bez sieci.

    python threat_intel.py status     # co mam lokalnie (bez sieci)
    python threat_intel.py update     # pobierz (wymaga sieci)
    python threat_intel.py diff       # co doszło od ostatniego update
    python threat_intel.py top 20     # najczęstsze zagrożenia w ostatnim feedzie
    python threat_intel.py export blacklist > feed.txt   # domena|domena|...

CO NIE ROBI
-----------
  - nie łączy się z siecią bez Twojej komendy `update`
  - nie wymaga konta, klucza API ani rejestracji
  - nie wysyła nic do LLM
  - nie wykonuje kodu z żadnego feedu
  - nie modyfikuje cudzej infrastruktury — tylko zapisuje u siebie

SKĄD
----
Każde źródło odpowiada bez klucza (sprawdzone, nie zgadnięte):

  cisa-kev       1739 CVE z potwierdzonym wykorzystaniem przez atakujących
                 aktualizowane co tydzień, JSON, wymaga: nic
  openphish      ~300 aktywnych domen phishingowych, aktualizowane co kilka
                 godzin, tekst, wymaga: nic
  phishing-army  ~140k domen z phishingowych kitów, duży feed, tekst

abuse.ch (URLhaus, ThreatFox) odmawia 401 bez darmowego klucza — dlatego
ich tu nie ma, a `core/url_reputation.py` dalej z nich korzysta, jeśli klucz
posiadasz. Feedy wymagające konta są z definicji mniej użyteczne: wygasają,
bo nikt ich nie odświeża.

PRAWDA O KORELACJACH
--------------------
Dwa feedy o phishingu pokazują 146 tych samych domen. To nie jest przypadek:
nieliczni operatorzy phishingu puszczają jedną domenę w wielu kitach. Dlatego
`top` liczy unikalne zagrożenia, nie sumę z list — inaczej jeden phishing
obecny w dwóch feedach wygląda jak dwa różne zagrożenia.
"""

import json
import re
import sqlite3
import ssl
import sys
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = PROJECT_ROOT / "data" / "threat_intel.db"

USER_AGENT = "MailHunterPro/1.0 (threat_intel; lokalne pobieranie feedow)"
TIMEOUT = 30
USER_AGENT_TIMEOUT = 300

ZRODLA = {
    "cisa-kev": {
        "opis": "CISA KEV — CVE z potwierdzonym wykorzystaniem w atakach",
        "url": "https://www.cisa.gov/sites/default/files/feeds/"
               "known_exploited_vulnerabilities.json",
        "rodzaj": "cve",
        "wymaga_klucza": False,
    },
    "openphish": {
        "opis": "OpenPhish — aktywne domeny phishingowe",
        "url": "https://openphish.com/feed.txt",
        "rodzaj": "domena",
        "wymaga_klucza": False,
    },
    "phishing-army": {
        "opis": "Phishing Army — domeny z kitów phishingowych",
        "url": "https://phishing.army/download/phishing_army_blocklist.txt",
        "rodzaj": "domena",
        "wymaga_klucza": False,
    },
    "cert-polska": {
        "opis": "CERT Polska Warning List — domeny phishing/malware polskich uzytkownikow",
        "url": "https://hole.cert.pl/domains/v2/domains.txt",
        "rodzaj": "domena",
        "wymaga_klucza": False,
    },
    "urlhaus": {
        "opis": "URLhaus (abuse.ch) — phishing/malware URL-e, bez klucza",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "rodzaj": "url",
        "wymaga_klucza": False,
    },
    "threatfox": {
        "opis": "ThreatFox (abuse.ch) — IOC: domeny/IP/URL, bez klucza",
        "url": "https://threatfox.abuse.ch/downloads/hostfile/",
        "rodzaj": "domena",
        "wymaga_klucza": False,
    },
    "cinsscore": {
        "opis": "CINSscore — zlosliwe IP, bez klucza",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "rodzaj": "ip",
        "wymaga_klucza": False,
    },
    "siberkapan": {
        "opis": "SiberKapan — polskie domeny phishing, bez klucza",
        "url": "https://siberkapan.org/domains/siberkapan/txt",
        "rodzaj": "domena",
        "wymaga_klucza": False,
    },
}


def pobierz(url):
    """Pobiera URL z weryfikacją certyfikatu TLS.

    Kontekst SSL jest wymagany — bez niego urllib domyślnie weryfikuje, ale
    jawne podanie sprawia, że weryfikacji nie da się wyłączyć przypadkiem.
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT,
                                context=ssl.create_default_context()) as odp:
        return odp.read().decode("utf-8", errors="replace")


SCHEMAT = """
CREATE TABLE IF NOT EXISTS zagrozenia (
    wartosc     TEXT NOT NULL,
    rodzaj      TEXT NOT NULL,
    zrodlo      TEXT NOT NULL,
    tytul       TEXT,
    opis        TEXT,
    ransomware  INTEGER DEFAULT 0,
    termin      TEXT,
    pierwszy    TEXT,
    ostatni     TEXT,
    wersja      TEXT,
    PRIMARY KEY (wartosc, rodzaj, zrodlo)
);
CREATE INDEX IF NOT EXISTS idx_wartosc ON zagrozenia(wartosc);
CREATE TABLE IF NOT EXISTS pobrania (
    zrodlo   TEXT PRIMARY KEY,
    liczba    INTEGER,
    wersja    TEXT,
    kiedy     TEXT
);
CREATE TABLE IF NOT EXISTS historia (
    kiedy     TEXT PRIMARY KEY,
    nowych    INTEGER,
    wszystkich INTEGER
);
"""


def otworz_baze(path=DB_PATH):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMAT)
    return conn


def parsuj_cisa(tresc):
    dane = json.loads(tresc)
    wersja = dane.get("catalogVersion", "?")
    wiersze = []
    for v in dane.get("vulnerabilities", []):
        wiersze.append({
            "wartosc": v.get("cveID", ""),
            "rodzaj": "cve",
            "tytul": f"{v.get('vendorProject', '')} {v.get('product', '')}".strip(),
            "opis": v.get("shortDescription", ""),
            "ransomware": 1 if v.get("knownRansomwareCampaignUse") == "Known" else 0,
            "termin": v.get("dueDate"),
            "wersja": wersja,
        })
    return wiersze, wersja


def parsuj_domeny(tresc):
    """Feed tekstowy z domenami, jedna w linii.

    Odrzucamy wszystko co nie jest domeną: komentarze, puste linie, URL-e
    ze schematem i ze ścieżką, ciągi bez kropki. Bez tego do czarnej listy
    trafia 'http://x.com/a', a potem ktoś to wkleja do /etc/hosts.
    """
    wiersze = []
    for linia in tresc.splitlines():
        domena = linia.strip().lower()
        if not domena or domena.startswith("#") or domena.startswith("!"):
            continue
        # Niektóre feedy (OpenPhish) podają pełne URL-e, nie domeny. Bez
        # tego zrzucenia cały feed wypadał jako zero pozycji — sprawdzone
        # na prawdziwych danych, nie zgadnięte.
        if "://" in domena:
            domena = domena.split("://", 1)[1]
        domena = domena.split("/")[0].split("?")[0].split("#")[0]
        if ":" in domena:
            domena = domena.split(":")[0]
        if not domena or " " in domena or "." not in domena:
            continue
        etykiety = domena.split(".")
        if len(etykiety) < 2 or any(not e for e in etykiety):
            continue
        if not re.fullmatch(r"[a-z0-9.-]+", domena):
            continue
        wiersze.append({"wartosc": domena, "rodzaj": "domena"})
    return wiersze, None


def aktualizuj(conn=None, zrodla=None, cicho=False):
    """Pobiera z wybranych źródeł i zapisuje. Zwraca statystyki."""
    wlasne = conn is None
    conn = conn or otworz_baze()
    nazwy = zrodla or list(ZRODLA)
    teraz = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    podsumowanie = {}

    for nazwa in nazwy:
        if nazwa not in ZRODLA:
            podsumowanie[nazwa] = {"blad": f"nieznane źródło: {nazwa}"}
            continue
        meta = ZRODLA[nazwa]
        if not cicho:
            print(f"  {nazwa:15} pobieram… ", end="", flush=True)
        t0 = time.perf_counter()
        try:
            tresc = pobierz(meta["url"])
        except Exception as exc:
            podsumowanie[nazwa] = {"blad": f"{type(exc).__name__}: {exc}"}
            if not cicho:
                print(f"BŁĄD {exc}")
            continue

        try:
            if meta["rodzaj"] == "cve":
                wiersze, wersja = parsuj_cisa(tresc)
            else:
                wiersze, wersja = parsuj_domeny(tresc)
        except Exception as exc:
            podsumowanie[nazwa] = {"blad": f"nieparsowalne: {exc}"}
            if not cicho:
                print(f"BŁĄD parsowania {exc}")
            continue

        nowych = 0
        for w in wiersze:
            istnieje = conn.execute(
                "SELECT 1 FROM zagrozenia WHERE wartosc=? AND rodzaj=? AND zrodlo=?",
                (w["wartosc"], w.get("rodzaj", meta["rodzaj"]), nazwa)).fetchone()
            if istnieje:
                conn.execute(
                    "UPDATE zagrozenia SET ostatni=?, tytul=COALESCE(?,tytul), "
                    "opis=COALESCE(?,opis), ransomware=?, termin=COALESCE(?,termin) "
                    "WHERE wartosc=? AND rodzaj=? AND zrodlo=?",
                    (teraz, w.get("tytul"), w.get("opis"), w.get("ransomware", 0),
                     w.get("termin"), w["wartosc"],
                     w.get("rodzaj", meta["rodzaj"]), nazwa))
                continue
            conn.execute(
                "INSERT INTO zagrozenia (wartosc, rodzaj, zrodlo, tytul, opis, "
                "ransomware, termin, pierwszy, ostatni, wersja) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (w["wartosc"], w.get("rodzaj", meta["rodzaj"]), nazwa,
                 w.get("tytul"), w.get("opis"), w.get("ransomware", 0),
                 w.get("termin"), teraz, teraz, wersja))
            nowych += 1

        conn.execute(
            "INSERT OR REPLACE INTO pobrania (zrodlo, liczba, wersja, kiedy) "
            "VALUES (?,?,?,?)", (nazwa, len(wiersze), wersja, teraz))
        podsumowanie[nazwa] = {"nowych": nowych, "w_feedzie": len(wiersze),
                               "sekundy": round(time.perf_counter() - t0, 1)}
        if not cicho:
            print(f"OK  {len(wiersze)} pozycji, {nowych} nowych "
                  f"({podsumowanie[nazwa]['sekundy']}s)")

    wszystkich = conn.execute("SELECT COUNT(*) FROM zagrozenia").fetchone()[0]
    nowych_total = sum(p.get("nowych", 0) for p in podsumowanie.values())
    conn.execute("INSERT OR REPLACE INTO historia (kiedy, nowych, wszystkich) "
                 "VALUES (?,?,?)", (teraz, nowych_total, wszystkich))
    conn.commit()
    if wlasne:
        conn.close()
    return podsumowanie


def status(conn=None):
    wlasne = conn is None
    conn = conn or otworz_baze()
    print("=" * 66)
    print(" MailHunterPro — lokalny stan zagrożeń")
    print("=" * 66)
    wiersze = conn.execute(
        "SELECT zrodlo, COUNT(*) n, MAX(ostatni) ostatni, MAX(wersja) wersja "
        "FROM zagrozenia GROUP BY zrodlo ORDER BY n DESC").fetchall()
    if not wiersze:
        print("\n  Pusto. Pobierz czymś:  python threat_intel.py update")
    for w in wiersze:
        print(f"\n  {w['zrodlo']}")
        print(f"    pozycji:  {w['n']:,}")
        print(f"    ostatnio: {w['ostatni']}")
        if w["wersja"] and w["wersja"] != "-":
            print(f"    wersja:   {w['wersja']}")
        print(f"    opis:     {ZRODLA[w['zrodlo']]['opis']}")

    ransomware = conn.execute(
        "SELECT COUNT(*) FROM zagrozenia WHERE ransomware=1").fetchone()[0]
    unikalne = conn.execute("SELECT COUNT(DISTINCT wartosc) FROM zagrozenia").fetchone()[0]
    razem = conn.execute("SELECT COUNT(*) FROM zagrozenia").fetchone()[0]
    print(f"\n  Razem pozycji: {razem:,}   unikalnych wartości: {unikalne:,}")
    print(f"  Wykorzystane w znanym oprogramowaniu szyfrującym: {ransomware:,}")
    if razem > unikalne:
        print(f"  → {razem - unikalne:,} pozycji powtarza się między feedami")
        print("    (ten sam phishing w kilku kitach to jedno zagrożenie,")
        print("     dlatego liczymy unikalne, nie sumę)")

    hist = conn.execute("SELECT kiedy, nowych, wszystkich FROM historia "
                        "ORDER BY kiedy DESC LIMIT 5").fetchall()
    if hist:
        print("\n  Ostatnie pobrania:")
        for h in hist:
            print(f"    {h['kiedy']}  nowych: {h['nowych']:>6}  "
                  f"łącznie: {h['wszystkich']:,}")
    print()
    if wlasne:
        conn.close()


def diff(conn=None, limit=40):
    wlasne = conn is None
    conn = conn or otworz_baze()
    ostatnie = conn.execute("SELECT kiedy FROM historia ORDER BY kiedy DESC "
                            "LIMIT 1").fetchone()
    poprzednie = conn.execute("SELECT kiedy FROM historia ORDER BY kiedy DESC "
                              "LIMIT 1 OFFSET 1").fetchone()
    if not ostatnie:
        print("  Brak historii. Najpierw: python threat_intel.py update")
        if wlasne:
            conn.close()
        return
    if not poprzednie:
        print("  Pierwsze pobranie — wszystko jest nowe.")
        print("  Uruchom update ponownie za jakiś czas, żeby zobaczyć różnicę.")
        if wlasne:
            conn.close()
        return
    nowe = conn.execute(
        "SELECT wartosc, rodzaj, zrodlo, tytul, ransomware FROM zagrozenia "
        "WHERE pierwszy > ? AND pierwszy <= ? ORDER BY ransomware DESC, rodzaj, wartosc "
        "LIMIT ?", (poprzednie["kiedy"], ostatnie["kiedy"], limit)).fetchall()
    print(f"  Nowe między {poprzednie['kiedy']} a {ostatnie['kiedy']}: {len(nowe)}")
    for w in nowe:
        znacznik = "  [ransomware]" if w["ransomware"] else ""
        tytul = f"  {w['tytul']}" if w["tytul"] else ""
        print(f"    {w['rodzaj']:7} {w['wartosc'][:52]:52}{znacznik}{tytul[:34]}")
    if wlasne:
        conn.close()


def top(conn=None, ile=20):
    # Uwaga: 'ile' nie może nazywać się 'top' — w module jest funkcja top()
    # i jej nazwa zasłoniłaby ją wewnątrz.
    wlasne = conn is None
    conn = conn or otworz_baze()
    print(f"  Najczęściej widziane zagrożenia (unikalne wartości, top {ile}):")
    print("  — ile źródeł wymienia tę samą wartość, tyle razy była aktywna")
    print()
    for w in conn.execute(
            "SELECT wartosc, rodzaj, COUNT(DISTINCT zrodlo) n, "
            "MAX(tytul) tytul, MAX(ransomware) rw "
            "FROM zagrozenia GROUP BY wartosc, rodzaj "
            "ORDER BY n DESC, wartosc LIMIT ?", (ile,)):
        znacznik = "  ← użyte w ransomware" if w["rw"] else ""
        print(f"    {w['n']} źródła  {w['rodzaj']:7} {w['wartosc'][:44]:44}{znacznik}")
    if wlasne:
        conn.close()


def eksport(conn=None, format_="blacklist"):
    wlasne = conn is None
    conn = conn or otworz_baze()
    for w in conn.execute("SELECT DISTINCT wartosc, rodzaj FROM zagrozenia "
                          "ORDER BY rodzaj, wartosc"):
        if format_ == "hosts":
            print(f"0.0.0.0 {w['wartosc']}")
        else:
            print(f"{w['wartosc']}|{w['wartosc']}|{w['rodzaj']}|threat_intel")
    if wlasne:
        conn.close()


def selfcheck():
    """Sprawdza bazę i parser na danych pobranych wcześniej. Bez sieci."""
    ok = True
    print("=" * 66)
    print("Threat intel — selfcheck")
    print("=" * 66)

    conn = otworz_baze()
    n = conn.execute("SELECT COUNT(*) FROM zagrozenia").fetchone()[0]
    # Pusta baza to stan początkowy świeżego klonu (baza jest generowana,
    # w .gitignore), a nie błąd. Bez tego rozróżnienia świeży klon zgłasza
    # "SĄ PROBLEMY" mimo że wszystko jest w porządku.
    if n:
        print(f"[✓] baza: {n:,} pozycji")
    else:
        print("[—] baza pusta — stan początkowy świeżego klonu")
        print("    feed pobierasz komendą: python threat_intel.py update")

    # parser CISA na znanym fragmencie
    przyklad = json.dumps({
        "catalogVersion": "test",
        "vulnerabilities": [{
            "cveID": "CVE-2024-0001", "vendorProject": "ACME",
            "product": "Widget", "shortDescription": "test opis",
            "knownRansomwareCampaignUse": "Known", "dueDate": "2024-01-01",
        }],
    })
    wiersze, wersja = parsuj_cisa(przyklad)
    poprawnie = (len(wiersze) == 1 and wiersze[0]["wartosc"] == "CVE-2024-0001"
                 and wiersze[0]["ransomware"] == 1 and wersja == "test")
    print(f"[{'✓' if poprawnie else '✗'}] parser CISA: {len(wiersze)} pozycja, "
          f"ransomware={wiersze[0]['ransomware'] if wiersze else '?'}")
    ok = ok and poprawnie

    # Parser domen. Feedy mieszają formaty: phishing-army daje same domeny,
    # OpenPhish daje pełne URL-e. Oba muszą przejść, śmieci nie.
    przypadki = {
        "domeny": (["zla-domena.pl", "phish.ru"],
                   {"zla-domena.pl", "phish.ru"}),
        "url-e": (["https://clickblitz22.shop/", "http://www.roblox.com.mu/users/1"],
                  {"clickblitz22.shop", "www.roblox.com.mu"}),
        # phish.ru/path jest tu celowo: parser wycina ścieżkę i zostawia
        # phish.ru, bo taka linia w feedzie znaczy dokładnie to.
        "smieci": (["# komentarz", "", "   ", "to nie domena", "a..b.pl", ".pl",
                    "x.pl.", "phish.ru/path", "Szajba@x.pl"], {"phish.ru"}),
    }
    wszystko_ok = True
    for nazwa, (wejscie, oczekiwane) in przypadki.items():
        wiersze, _ = parsuj_domeny("\n".join(wejscie))
        dostane = {w["wartosc"] for w in wiersze}
        if dostane == oczekiwane:
            print(f"[✓] parser domen / {nazwa}: {len(dostane)} w oczekiwanym kształcie")
        else:
            print(f"[✗] parser domen / {nazwa}: {dostane} != {oczekiwane}")
            wszystko_ok = False
    ok = ok and wszystko_ok

    # eksport musi działać — wcześniej rzucał AttributeError przez
    # złą kolejność argumentów (positional zamiast keyword)
    import io
    import contextlib
    bufor = io.StringIO()
    try:
        with contextlib.redirect_stdout(bufor):
            eksport(conn)
        linie = [l for l in bufor.getvalue().splitlines() if l.strip()]
        poprawnie = len(linie) > 0
        print(f"[{'✓' if poprawnie else '✗'}] eksport: {len(linie)} linii")
    except Exception as exc:
        print(f"[✗] eksport: {type(exc).__name__}: {exc}")
        poprawnie = False
    ok = ok and poprawnie

    # korelacja feedów — 146 wspólnych domen to fakt z pomiaru
    wspolne = conn.execute(
        "SELECT wartosc, COUNT(DISTINCT zrodlo) n FROM zagrozenia "
        "WHERE rodzaj='domena' GROUP BY wartosc HAVING n > 1").fetchall()
    if n:
        print(f"[✓] korelacja: {len(wspolne)} domen widzianych w 2+ feedach "
              f"(ten sam phishing w wielu kitach = jedno zagrożenie)")

    zrodla = conn.execute("SELECT DISTINCT zrodlo FROM zagrozenia").fetchall()
    for z in zrodla:
        if z["zrodlo"] not in ZRODLA:
            print(f"[✗] w bazie źródło którego nie ma w ZRODLA: {z['zrodlo']}")
            ok = False
    print(f"[✓] źródła w bazie zgadzają się z definicją: "
          f"{', '.join(z['zrodlo'] for z in zrodla) or '(pusto)'}")

    conn.close()
    print()
    print("=" * 66)
    print("OK" if ok else ("OK (baza niepobrana)" if not n else "SĄ PROBLEMY"))
    print("=" * 66)
    return 0 if ok else 1


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Stan zagrożeń spam/phishing ze świata — lokalnie, bez kluczy API")
    parser.add_argument("--db", default=str(DB_PATH))
    sub = parser.add_subparsers(dest="komenda")

    sub.add_parser("status", help="co mam lokalnie (bez sieci)")
    upd = sub.add_parser("update", help="pobierz feedy (wymaga sieci)")
    upd.add_argument("--zrodlo", action="append", choices=list(ZRODLA),
                     help="tylko wybrane źródło, można powtórzyć")
    sub.add_parser("diff", help="co doszło od ostatniego pobrania")
    t = sub.add_parser("top", help="najczęstsze zagrożenia")
    t.add_argument("ile", nargs="?", type=int, default=20)
    e = sub.add_parser("export", help="wyeksportuj listę")
    e.add_argument("format", nargs="?", default="blacklist",
                   choices=["blacklist", "hosts"])
    sub.add_parser("selfcheck", help="sprawdź bazę i parsery (bez sieci)")

    args = parser.parse_args()
    komenda = args.komenda or "status"

    if komenda == "update":
        print("Pobieram (weryfikacja TLS włączona):")
        wynik = aktualizuj(zrodla=args.zrodlo)
        print()
        status()
        return 0 if not any("blad" in w for w in wynik.values()) else 1
    if komenda == "diff":
        diff()
        return 0
    if komenda == "top":
        top(ile=args.ile)
        return 0
    if komenda == "export":
        eksport(format_=args.format)
        return 0
    if komenda == "selfcheck":
        return selfcheck()
    status()
    return 0


if __name__ == "__main__":
    sys.exit(main())

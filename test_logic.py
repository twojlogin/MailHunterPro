import re

def analyze_logic_test(subject, body):
    score = 0
    flags = []
    
    # Twoja logika z plików + mały upgrade 2026
    indicators = {
        'pilne': 25, 'faktura': 20, 'zaległość': 30, 'komornik': 40,
        'bit.ly': 35, 't.ly': 35, 'tinyurl': 30, 'link.tree': 20,
        'zaloguj': 15, 'weryfikacja': 20, 'bezpieczeństwo': 10
    }
    
    for word, points in indicators.items():
        if word in subject.lower() or word in body.lower():
            score += points
            flags.append(word.upper())
            
    # Test na ukryte linki (prosty regex)
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
    if len(urls) > 3:
        score += 15
        flags.append("MANY_LINKS")

    return score, flags

# TEST: Udajemy maila od "InPostu"
s = "⚠️ PILNE: Twoja paczka została wstrzymana! Zaległość 1.50 PLN"
b = "Twoja paczka czeka w magazynie. Prosimy o opłacenie faktury: http://bit.ly/paczka-2026"

score, reasons = analyze_logic_test(s, b)
print(f"Wynik analizy dla Arka:\nScore: {score}/100\nFlagi: {reasons}")
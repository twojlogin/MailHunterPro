# Śmieci — nie używaj tego

Pliki tu przeniesione, bo są martwe. Sprawdzone: żaden nie jest importowany
przez nic w projekcie (`grep -rl` po wszystkich `.py` → 0 trafień).

## mailhunter_requirements.py
`requirements.txt` wyłożony na `.py`. 66 linii pakietów z innymi wersjami
(`==` zamiast `>=`) i **bez `flask`**, którego wymaga `web/server.py`.
Podwójne źródło prawdy, w którym nowy pakiet łatwo pominąć.
Prawdziwy: `requirements.txt` na górze repo.

## mailhunter_quick_test.py
Import tego pliku pyta o połączenie z prawdziwym kontem Gmail:
`input("Czy chcesz przetestować logowanie do prawdziwego konta Gmail? (t/N): ")`
Kończy się `EOFError` przy imporcie w środowisku bez wejścia.
Test nie powinien mieć interakcji w imporcie.

## test_logic.py
31 linii, nazwa `test_*` bez funkcji testowych. `pytest` tego nie zbiera.
Kolejny plik, który wygląda jak test, a nie jest.

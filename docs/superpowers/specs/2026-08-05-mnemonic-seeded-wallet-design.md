# Portfel wyprowadzany z frazy mnemonicznej (24 słowa)

Data: 2026-08-05

## Kontekst

Dziś klucze portfela powstają z systemowego CSPRNG wewnątrz liboqs i nie da się ich
odtworzyć bez pliku portfela. `wallet.GetMnemonicWords` (`wallet/wallet.go:431`) próbuje
iść w odwrotną stronę — zakodować istniejący klucz prywatny jako frazę BIP39 — co jest
niewykonalne dla kluczy post-kwantowych (Falcon-512 ma ~1281 bajtów, BIP39 mieści 64) i
dlatego zwraca błąd (CW-M2). W efekcie jedyną kopią zapasową jest zaszyfrowany plik.

Zmieniamy kierunek: **najpierw fraza, potem klucze**. Fraza staje się jedynym materiałem,
który użytkownik musi zabezpieczyć, i wystarcza do odtworzenia portfela na czystej maszynie.

## Decyzje przyjęte przed projektowaniem

1. **Jeden portfel = jedna fraza 24-słowa**, z której wyprowadzane są klucze dla **każdego**
   schematu podpisu — obecnych (Falcon-512, MAYO-5) i przyszłych, wybranych przez głosowanie
   w łańcuchu.
2. **Istniejące portfele działają dalej** bez frazy; nie ma migracji przymusowej.
3. **Fraza nigdy nie opuszcza maszyny**: obsługiwana wyłącznie przez `cmd/generateNewWallet`
   i `cmd/gui`. Endpointy HTTP `/api/wallet/mnemonic` w `cmd/webui` i `cmd/website` zostają
   wyłączone na stałe.
4. **Ziarno jest przechowywane w pliku portfela**, zaszyfrowane tą samą ścieżką co klucze.

## Analiza bezpieczeństwa, która ukształtowała projekt

### Liczba kombinacji

| | bity | entropia + suma kontrolna | ważnych mnemoników |
|---|---|---|---|
| 12 słów | 132 | 128 + 4 | 2^128 ≈ 3,40×10³⁸ |
| 24 słowa | 264 | 256 + 8 | 2^256 ≈ 1,16×10⁷⁷ |

Naiwne `2048^12 = 2^132` i `2048^24 = 2^264` są zawyżone — suma kontrolna odrzuca 15/16
kombinacji przy 12 słowach i 255/256 przy 24.

### Dlaczego wyłącznie 24 słowa

Po tej zmianie bezpieczeństwo klucza przestaje wynikać z siły schematu, a zaczyna z entropii
ziarna. 12 słów to 128 bitów, czyli **2^64 operacji pod algorytmem Grovera** — dla łańcucha,
którego celem jest odporność kwantowa, byłoby to zaprzeczenie założeń. 24 słowa dają 2^128
kwantowo. Wariant 12-słowy nie jest udostępniany.

### Zmiana modelu zagrożeń

Dziś klucze Falcona i MAYO są niezależne: atakujący musi złamać oba schematy. Po zmianie oba
pochodzą z jednego ziarna, więc odgadnięcie ziarna daje oba klucze. Niezależność schematów
chroni nadal przed złamaniem samego algorytmu, ale nie przed odgadnięciem ziarna. Jest to
świadomie zaakceptowany koszt odtwarzalności; rekompensuje go 256-bitowa entropia ziarna.

### Czy frazę da się odtworzyć z podpisów w łańcuchu

Matematycznie nie — Falcon-512 i MAYO-5 są EUF-CMA, opublikowany podpis nie ujawnia klucza
prywatnego. Istnieje natomiast **realna droga implementacyjna**, którą ta zmiana otwiera i
którą projekt musi zamknąć:

- `crypto/oqs/rand.RandomBytesCustomAlgorithm` (`crypto/oqs/rand/rand.go:103`) podmienia RNG
  **globalnie dla całego procesu**.
- Falcon losuje przy każdym podpisie 40-bajtową sól i 48-bajtowe ziarno samplera
  (`liboqs/src/sig/falcon/pqclean_falcon-512_clean/pqclean.c:177` i `:192`).
  MAYO losuje sól (`liboqs/src/sig/mayo/*/mayo.c:418`).
- Deterministyczny RNG pozostawiony włączony ⇒ powtórzona sól ⇒ **odzyskanie klucza
  prywatnego z dwóch podpisów widocznych w blockchainie**.

`OQS_SIG_verify` nie sięga po losowość, więc weryfikacja bloków pozostaje nietknięta.

### Wykonalność determinizmu

Oba schematy pobierają przy generowaniu klucza **dokładnie jeden bufor stałej długości**, po
czym rozwijają go deterministycznie:

| schemat | keygen | źródło |
|---|---|---|
| Falcon-512 | `randombytes(seed, 48)` → SHAKE256 | `pqclean.c:60` |
| MAYO-5 | `randombytes(seed_sk, param_sk_seed_bytes)` → ekspansja | `mayo.c:564` |

Brak pętli odrzucania oznacza, że liczba bajtów pobranych z RNG nie zależy od danych, więc
derywacja jest stabilna.

Wariant „czysty" — API `keypair_derand` przyjmujące ziarno jawnie — **nie istnieje w przypiętej
wersji liboqs (8ee6039)** dla żadnego schematu. Fork liboqs odrzucono jako nieproporcjonalny
koszt utrzymania.

## Architektura

Trzy elementy, każdy z jedną odpowiedzialnością:

| Miejsce | Odpowiedzialność | Nie zależy od |
|---|---|---|
| `wallet/mnemonic.go` (nowy) | fraza ↔ ziarno (BIP39 + HKDF) | liboqs, RNG |
| `crypto/oqs/deterministic.go` (nowy) | keygen z ziarna pod strażą RNG | BIP39, portfela |
| `crypto/oqs/oqs.go` (zmiana) | mutex chroniący losowy stan liboqs | reszty |

### Łańcuch derywacji

```
crypto/rand → 32 B entropii
  → bip39.NewMnemonic          → 24 słowa (256 bitów + 8 sumy kontrolnej)
  → PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048 iteracji) → 64 B ziarna głównego
  → HKDF-SHA512(ikm=ziarno, salt="qwid-wallet-v1", info=sigName‖0x00‖rola)
  → strumień bajtów podawany liboqs przy generowaniu klucza
```

`rola` ∈ {`primary`, `secondary`}; `sigName` to nazwa schematu. Jeden mnemonic obsługuje
dowolny schemat wybrany przez głosowanie, a klucze poszczególnych schematów i ról są
kryptograficznie rozdzielone.

`DeriveKeySeed` zwraca **64 bajty** ziarna klucza. Shim w `crypto/oqs` używa ich jako klucza
strumienia HKDF-Expand-SHA512 i wydaje z niego tyle bajtów, ile liboqs poprosi w danym
wywołaniu — dzięki temu ta sama derywacja obsługuje schematy o różnych rozmiarach ziarna
(Falcon 48 B, MAYO `param_sk_seed_bytes`) bez zmian w `wallet/mnemonic.go`.

### Interfejsy

```go
// wallet/mnemonic.go
func NewMnemonic24() ([]byte, error)                     // crypto/rand; []byte, aby dało się wyzerować
func SeedFromMnemonic(mnemonic []byte) ([]byte, error)   // waliduje sumę kontrolną i długość 24
func DeriveKeySeed(seed []byte, sigName string, primary bool) []byte

// crypto/oqs/deterministic.go
func (sig *Signature) GenerateKeyPairFromSeed(seed []byte) (pub []byte, drawn int, err error)
```

### Argument bezpieczeństwa

Pakietowy `randMutex` w `crypto/oqs` jest trzymany przez **wszystkie trzy** operacje sięgające
po losowość: `Sign` (`crypto/oqs/oqs.go:420`), `GenerateKeyPair` (`:400`) oraz nowe
`GenerateKeyPairFromSeed`. Deterministyczny RNG jest instalowany wyłącznie wewnątrz
`GenerateKeyPairFromSeed`, pod tym mutexem, i przywracany na `"system"`
(`OQS_RAND_alg_system`, `/usr/local/include/oqs/rand.h:22`) w `defer` — także przy panice.

Stąd: **żadna operacja podpisywania nie może zaobserwować deterministycznego RNG**, więc sole
Falcona i MAYO zawsze pochodzą z systemowego CSPRNG. Droga „powtórzona sól → klucz z
podpisów" zostaje zamknięta.

Koszt: podpisywanie zostaje zserializowane. Bez znaczenia w praktyce — węzeł podpisuje rzadko
(nonce raz na blok), a częsta weryfikacja mutexa nie dotyka.

Druga linia obrony: shim zlicza pobrane bajty i zwraca tę liczbę, co pozwala przypiąć
zachowanie liboqs testem.

## Przepływy

### Tworzenie nowego portfela (`cmd/generateNewWallet`, `cmd/gui`)

1. `NewMnemonic24()`.
2. Fraza pokazana **przed** utworzeniem portfela, z wymuszonym potwierdzeniem: użytkownik
   wpisuje trzy słowa z podanych pozycji.
3. `SeedFromMnemonic` → `DeriveKeySeed` dla obu ról.
4. `GenerateKeyPairFromSeed` zamiast `GenerateKeyPair` w `GenerateNewAccount`
   (`wallet/wallet.go:268`).
5. Dalej bez zmian: hasło, `Iv`, `KdfSalt`, szyfrowanie, `StoreJSON`.
6. Ziarno zapisane w `EncryptedSeed`; mnemonic wyzerowany w pamięci przed powrotem.

### Odtwarzanie z frazy

`cmd/generateNewWallet` dostaje tryb „odtwórz": 24 słowa + numer portfela + **nowe** hasło.
Ta sama ścieżka co tworzenie, ziarno pochodzi z podanej frazy. Na koniec pokazywany jest
odtworzony adres do potwierdzenia. Odmawiamy nadpisania zajętego numeru portfela bez jawnego
potwierdzenia.

Które schematy odtwarzamy: na czystej maszynie nie ma pliku portfela, więc `Accounts`
(`wallet/wallet.go:66`) jest puste — odtwarzamy klucze dla dwóch schematów aktywnych w chwili
odtwarzania (`common.SigName()`, `common.SigName2()`). Jeśli plik portfela istnieje i zawiera
wpisy dla dodatkowych schematów, odtwarzamy również je. Klucze dla schematów historycznych,
o których nie wiemy, można odtworzyć później — wystarczy uruchomić odtwarzanie ponownie, gdy
nazwa schematu jest znana, bo derywacja jest w pełni deterministyczna.

### Zmiana schematu szyfrowania w łańcuchu

`AddNewEncryptionToActiveWallet` (`wallet/wallet.go:310`) woła dziś `signer.GenerateKeyPair()`.
Zmiana: jeśli portfel ma `EncryptedSeed`, klucz powstaje z
`GenerateKeyPairFromSeed(DeriveKeySeed(ziarno, sigName, primary))`. Bez tego mnemonic
przestałby wystarczać do odtworzenia portfela po pierwszym głosowaniu, a węzeł działający
24/7 nie może prosić operatora o wpisanie frazy.

Portfele bez ziarna zachowują dotychczasowe, losowe generowanie, z ostrzeżeniem w logu, że
powstały klucz nie będzie odtwarzalny z frazy.

### Interfejsy sieciowe

`GetMnemonic` w `cmd/webui/handlers/handlers.go:308` oraz odpowiednik w `cmd/website` zwracają
na stałe komunikat, że fraza jest dostępna wyłącznie lokalnie. Trasy pozostają zarejestrowane,
żeby klienci dostali czytelną odpowiedź zamiast 404.

## Format pliku portfela

Nowe pole w strukturze `Wallet` (`wallet/wallet.go:50`):

```go
EncryptedSeed []byte `json:"encrypted_seed,omitempty"`
```

Szyfrowane tą samą ścieżką co klucze prywatne (`w.encrypt`, AES-256-GCM z kluczem Argon2id).
`omitempty` sprawia, że stare pliki ładują się bez zmian.

Pogorszenie bezpieczeństwa jest marginalne: kto ma plik i hasło, ma już wszystkie klucze
prywatne. Ziarno dokłada do tego jedynie klucze dla schematów jeszcze nieużywanych.

## Obsługa błędów i przypadki brzegowe

| Sytuacja | Zachowanie |
|---|---|
| Zła suma kontrolna, słowo spoza listy, zła liczba słów | `SeedFromMnemonic` zwraca konkretny błąd; wymuszamy dokładnie 24 słowa, choć biblioteka przyjmuje też 12/15/18/21/48 |
| Panika w liboqs podczas keygenu | `defer` przywraca `"system"` |
| Nieudane przywrócenie RNG | `logger.Fatal` — zatrzymanie węzła. Podpisywanie deterministycznym RNG jest gorsze niż przestój: ujawnia klucz przez łańcuch |
| Stary portfel + głosowanie zmieniło schemat | Klucz losowy jak dziś, plus ostrzeżenie w logu |
| Odtwarzanie na zajęty numer portfela | Odmowa nadpisania bez jawnego potwierdzenia |
| Zerowanie pamięci | Mnemonic i ziarno jako `[]byte`, nie `string` — `string` jest niemutowalny; wzorzec już obecny w `wallet/wallet.go:51` |

## Testy

Dwa testy są krytyczne:

**Known-answer test.** Przypięty mnemonic → przypięty adres, osobno dla Falcon-512 i MAYO-5.
Jedyna rzecz, która wychwyci, że aktualizacja liboqs, zmiana HKDF albo inna kolejność bajtów
sprawiły, że ta sama fraza odtwarza **inny** portfel. Bez tego testu taka zmiana przechodzi po
cichu i odcina użytkowników od środków.

**Test losowości soli.** Po wygenerowaniu klucza z ziarna podpisujemy dwie różne wiadomości i
sprawdzamy, że podpisy się różnią — bezpośredni test regresyjny na scenariusz „powtórzona sól
→ odzyskanie klucza z podpisów w blockchainie". Wersja z `-race`: równoległe `Sign` i
`GenerateKeyPairFromSeed`.

Pozostałe:

- Licznik pobranych bajtów: Falcon-512 dokładnie 48 B, MAYO-5 dokładnie `param_sk_seed_bytes`.
- Determinizm: ta sama fraza → ten sam adres; różne frazy → różne adresy.
- Rozdzielenie dziedzin: `primary` ≠ `secondary` dla tego samego schematu; `Falcon-512` ≠
  `MAYO-5` dla tej samej roli.
- Pełny cykl odtwarzania: utwórz → zapisz frazę i adres → skasuj plik → odtwórz → ten sam
  adres, podpis weryfikowalny wcześniejszym kluczem publicznym.
- Przywrócenie RNG po panice w keygenie.
- Zgodność wstecz: portfel bez `encrypted_seed` ładuje się i podpisuje.
- Walidacja frazy: zła suma kontrolna, 12 słów, pusta, słowo spoza listy.

## Poza zakresem

- Opcjonalne hasło BIP39 („25. słowo") — podwaja liczbę rzeczy, których utrata oznacza utratę
  środków.
- Kreator migracji istniejących portfeli na format z frazą (przeniesienie środków i stake'u
  nowym adresem) — osobny etap, jeśli okaże się potrzebny.
- Wsparcie dla fraz 12-słowych — świadomie odrzucone, patrz analiza bezpieczeństwa.

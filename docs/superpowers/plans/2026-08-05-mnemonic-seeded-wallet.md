# Portfel wyprowadzany z frazy mnemonicznej — plan implementacji

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Portfel powstaje z 24-słowej frazy BIP39, którą można podać ponownie na czystej maszynie i odtworzyć te same klucze Falcon-512 i MAYO-5.

**Architecture:** Fraza → ziarno BIP39 (PBKDF2-HMAC-SHA512) → HKDF-SHA512 z rozdzieleniem dziedzin po nazwie schematu i roli → strumień bajtów podawany liboqs przez tymczasowo zainstalowany, deterministyczny RNG. Kluczowy element bezpieczeństwa: RNG liboqs jest globalny dla procesu, więc pakietowy mutex w `crypto/oqs` gwarantuje, że żadne podpisywanie nie zaobserwuje deterministycznego RNG — inaczej powtórzone sole Falcona pozwoliłyby odzyskać klucz z podpisów widocznych w blockchainie.

**Tech Stack:** Go 1.23.6, cgo + liboqs (przypięte na 8ee6039), `github.com/wonabru/bip39`, `golang.org/x/crypto/hkdf`, `golang.org/x/crypto/argon2`.

**Spec:** `docs/superpowers/specs/2026-08-05-mnemonic-seeded-wallet-design.md`

## Global Constraints

- Każde `go build` / `go test` wymaga flag CGO i pełnej ścieżki do Go (`unset GOROOT` — samo `go` ma niezgodny GOROOT):

  ```bash
  unset GOROOT
  export CGO_CFLAGS="-isystem $HOME/local/include"
  export CGO_LDFLAGS="-L$HOME/local/lib -L/usr/local/intelpython3/lib -lrocksdb -lstdc++ -lm -lz -lsnappy -llz4 -lzstd -lbz2 -lpthread -ldl"
  GO=/usr/local/go/bin/go
  ```

  W dalszej części planu `$GO` oznacza `/usr/local/go/bin/go` z ustawionymi powyżej zmiennymi.
- Wyłącznie frazy **24-słowe** (256 bitów entropii). Warianty 12/15/18/21/48-słowe są odrzucane, mimo że biblioteka je przyjmuje.
- Sól HKDF: dokładnie `"qwid-wallet-v1"`. Info: `sigName ‖ 0x00 ‖ rola`, gdzie rola to `"primary"` albo `"secondary"`.
- Info strumienia RNG w `crypto/oqs`: dokładnie `"qwid-oqs-keygen-v1"`.
- Materiał sekretny (fraza, ziarno) przekazywany jako `[]byte`, nigdy `string` — `string` w Go jest niemutowalny, nie da się go wyzerować.
- Wiadomość commita kończy się linią `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`, a zaczyna identyfikatorem zadania `OB-56` (konwencja z `CLAUDE.md`).
- Nie zmieniamy zachowania portfeli bez pola `encrypted_mnemonic` — mają działać dokładnie jak dziś.
- **Każdy pakiet w `cmd/` pozostaje jednoplikowy.** `CLAUDE.md` i `README.md` dokumentują wywołania
  w postaci `go run cmd/<nazwa>/main.go`, a budowanie pojedynczego pliku nie widzi pozostałych
  plików pakietu. Kod pomocniczy dopisujemy do `main.go`; pliki `_test.go` są bezpieczne, bo testy
  zawsze budują cały pakiet.

## Struktura plików

| Plik | Odpowiedzialność | Zadanie |
|---|---|---|
| `wallet/mnemonic_seed.go` (nowy) | fraza ↔ ziarno, derywacja HKDF; zero zależności od liboqs | 1 |
| `wallet/mnemonic_seed_test.go` (nowy) | testy powyższego | 1 |
| `crypto/oqs/oqs.go` (zmiana) | `randMutex` chroniący `Sign` i `GenerateKeyPair` | 2 |
| `crypto/oqs/deterministic.go` (nowy) | keygen z ziarna pod strażą RNG | 2 |
| `crypto/oqs/deterministic_test.go` (nowy) | licznik bajtów, determinizm, przywrócenie RNG, losowość soli | 2 |
| `wallet/wallet.go` (zmiana) | pole `EncryptedMnemonic`, `seed`, `GenerateNewAccountFromSeed`, ładowanie ziarna, `Wipe` | 3 |
| `wallet/seed_persistence_test.go` (nowy) | zgodność wstecz i cykl zapis/odczyt ziarna | 3 |
| `wallet/wallet.go` (zmiana) | `AddNewEncryptionToActiveWallet` korzysta z ziarna | 4 |
| `wallet/wallet.go` (zmiana) | nowa semantyka `GetMnemonicWords` / `RestoreSecretKeyFromMnemonic` | 5 |
| `cmd/generateNewWallet/main.go` (zmiana) | tryby „utwórz" i „odtwórz" | 6 |
| `cmd/gui/qtwidgets/wallet.go` (zmiana) | pokazanie frazy i odtwarzanie w GUI | 7 |
| `cmd/webui/handlers/handlers.go`, `cmd/website/handlers/wallet_handlers.go` (zmiana) | trwałe wyłączenie frazy przez HTTP | 7 |
| `wallet/mnemonic_kat_test.go` (nowy) | known-answer test przypinający derywację | 8 |
| `CLAUDE.md`, `README.md` (zmiana) | dokumentacja | 8 |

---

### Task 1: Derywacja frazy i ziarna (`wallet/mnemonic_seed.go`)

Czysty Go, bez liboqs. Buduje fundament, na którym stoją wszystkie kolejne zadania.

**Files:**
- Create: `wallet/mnemonic_seed.go`
- Test: `wallet/mnemonic_seed_test.go`

**Interfaces:**
- Consumes: `github.com/wonabru/bip39` — `NewMnemonic(entropy []byte) (string, error)`, `MnemonicToByteArray(mnemonic string) ([]byte, error)` (validates the checksum; `IsMnemonicValid` does **not**), `NewSeed(mnemonic, password string) []byte`
- Produces:
  - `func NewMnemonic24() ([]byte, error)` — 24 słowa rozdzielone pojedynczymi spacjami
  - `func SeedFromMnemonic(mnemonic []byte) ([]byte, error)` — 64 bajty
  - `func DeriveKeySeed(seed []byte, sigName string, primary bool) []byte` — 64 bajty
  - `func ZeroBytes(b []byte)`
  - `const MnemonicWordCount = 24`

- [ ] **Step 1: Napisz test, który nie przechodzi**

Utwórz `wallet/mnemonic_seed_test.go`:

```go
package wallet

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewMnemonic24ReturnsTwentyFourWords(t *testing.T) {
	m, err := NewMnemonic24()
	if err != nil {
		t.Fatalf("NewMnemonic24() zwrócił błąd: %v", err)
	}
	words := strings.Fields(string(m))
	if len(words) != MnemonicWordCount {
		t.Fatalf("liczba słów = %d, oczekiwano %d", len(words), MnemonicWordCount)
	}
}

func TestNewMnemonic24IsDifferentEveryTime(t *testing.T) {
	a, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("dwie kolejne frazy są identyczne — entropia nie pochodzi z crypto/rand")
	}
}

func TestSeedFromMnemonicIsDeterministic(t *testing.T) {
	m, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	s1, err := SeedFromMnemonic(m)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := SeedFromMnemonic(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatal("ta sama fraza dała różne ziarna")
	}
	if len(s1) != 64 {
		t.Fatalf("długość ziarna = %d, oczekiwano 64", len(s1))
	}
}

func TestSeedFromMnemonicRejectsBadInput(t *testing.T) {
	valid, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(string(valid))

	cases := []struct {
		name     string
		mnemonic string
		wantMsg  string
	}{
		{"pusta", "", "24"},
		{"dwanaście słów", strings.Join(words[:12], " "), "24"},
		{"słowo spoza listy", strings.Join(append(append([]string{}, words[:23]...), "qwidqwid"), " "), "nieprawidłowa"},
		{"zła suma kontrolna", strings.Join(append(append([]string{}, words[:23]...), words[0]), " "), "nieprawidłowa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SeedFromMnemonic([]byte(tc.mnemonic))
			if err == nil {
				t.Fatal("oczekiwano błędu")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("komunikat %q nie zawiera %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestDeriveKeySeedSeparatesDomains(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 64)

	falconPrimary := DeriveKeySeed(seed, "Falcon-512", true)
	falconSecondary := DeriveKeySeed(seed, "Falcon-512", false)
	mayoPrimary := DeriveKeySeed(seed, "MAYO-5", true)

	if len(falconPrimary) != 64 {
		t.Fatalf("długość ziarna klucza = %d, oczekiwano 64", len(falconPrimary))
	}
	if bytes.Equal(falconPrimary, falconSecondary) {
		t.Fatal("role primary i secondary dały to samo ziarno")
	}
	if bytes.Equal(falconPrimary, mayoPrimary) {
		t.Fatal("różne schematy dały to samo ziarno")
	}
	if !bytes.Equal(falconPrimary, DeriveKeySeed(seed, "Falcon-512", true)) {
		t.Fatal("derywacja nie jest deterministyczna")
	}
}

func TestZeroBytesClears(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("bajt %d = %d, oczekiwano 0", i, v)
		}
	}
}
```

- [ ] **Step 2: Uruchom test i potwierdź, że nie przechodzi**

```bash
$GO test ./wallet/ -run 'TestNewMnemonic24|TestSeedFromMnemonic|TestDeriveKeySeed|TestZeroBytes' -v
```

Oczekiwane: błąd kompilacji `undefined: NewMnemonic24`.

- [ ] **Step 3: Napisz implementację**

Utwórz `wallet/mnemonic_seed.go`:

```go
package wallet

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"strings"

	"github.com/wonabru/bip39"
	"golang.org/x/crypto/hkdf"
)

// MnemonicWordCount is the only accepted phrase length. 24 words carry 256 bits
// of entropy; a 12-word phrase would carry 128, which Grover's algorithm reduces
// to 2^64 — unacceptable for a chain whose purpose is quantum resistance.
const MnemonicWordCount = 24

// mnemonicEntropyBytes is the entropy behind a 24-word phrase: 256 bits.
const mnemonicEntropyBytes = 32

// keySeedLength is the size of the per-key seed handed to the deterministic
// keygen. 64 bytes comfortably covers every scheme's seed draw (Falcon-512 takes
// 48, MAYO-5 fewer) and leaves headroom for future ones.
const keySeedLength = 64

// hkdfSalt separates this project's key derivation from any other use of the
// same BIP39 seed. Changing it invalidates every existing wallet — it is pinned
// by the known-answer test.
const hkdfSalt = "qwid-wallet-v1"

// NewMnemonic24 generates a fresh 24-word recovery phrase from the system CSPRNG.
// The phrase is returned as []byte, not string, so the caller can zero it.
func NewMnemonic24() ([]byte, error) {
	entropy := make([]byte, mnemonicEntropyBytes)
	if _, err := rand.Read(entropy); err != nil {
		return nil, fmt.Errorf("nie można pobrać entropii z systemowego CSPRNG: %w", err)
	}
	defer ZeroBytes(entropy)

	m, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("nie można zbudować frazy: %w", err)
	}
	return []byte(m), nil
}

// SeedFromMnemonic validates a recovery phrase and turns it into the 64-byte
// BIP39 seed (PBKDF2-HMAC-SHA512, 2048 iterations, empty passphrase).
func SeedFromMnemonic(mnemonic []byte) ([]byte, error) {
	phrase := strings.Join(strings.Fields(string(mnemonic)), " ")
	if n := len(strings.Fields(phrase)); n != MnemonicWordCount {
		return nil, fmt.Errorf("fraza musi mieć dokładnie %d słów, podano %d", MnemonicWordCount, n)
	}
	// bip39.IsMnemonicValid only checks word count and wordlist membership; it
	// does not verify the checksum bits. bip39.MnemonicToByteArray calls
	// IsMnemonicValid internally and then verifies the checksum, so it is the
	// only one of the two that actually rejects a mnemonic with a bad checksum.
	// This matters: without the checksum check a typo in a recovery phrase would
	// silently derive a different wallet instead of reporting an error.
	if _, err := bip39.MnemonicToByteArray(phrase); err != nil {
		return nil, fmt.Errorf("nieprawidłowa fraza: słowo spoza listy BIP39 albo błędna suma kontrolna")
	}
	return bip39.NewSeed(phrase, ""), nil
}

// DeriveKeySeed derives the per-key seed for one signature scheme and one role.
// Domain separation by scheme name means a single phrase covers whatever scheme
// the chain votes in later; separation by role keeps the primary and secondary
// keys independent of each other given only one of them.
func DeriveKeySeed(seed []byte, sigName string, primary bool) []byte {
	role := "secondary"
	if primary {
		role = "primary"
	}
	info := make([]byte, 0, len(sigName)+1+len(role))
	info = append(info, sigName...)
	info = append(info, 0x00)
	info = append(info, role...)

	out := make([]byte, keySeedLength)
	r := hkdf.New(sha512.New, seed, []byte(hkdfSalt), info)
	if _, err := io.ReadFull(r, out); err != nil {
		// HKDF-SHA512 can emit up to 16320 bytes; a 64-byte read cannot fail.
		panic("hkdf: " + err.Error())
	}
	return out
}

// ZeroBytes overwrites b in place. Use it on every buffer that held a phrase or
// a seed before letting it go out of scope.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
```

- [ ] **Step 4: Uruchom testy i potwierdź, że przechodzą**

```bash
$GO test ./wallet/ -run 'TestNewMnemonic24|TestSeedFromMnemonic|TestDeriveKeySeed|TestZeroBytes' -v
```

Oczekiwane: wszystkie PASS.

- [ ] **Step 5: Sprawdź, że nic innego się nie zepsuło**

```bash
$GO build ./... && $GO test ./wallet/
```

Oczekiwane: kompilacja bez błędów, cały pakiet `wallet` zielony.

- [ ] **Step 6: Commit**

```bash
git add wallet/mnemonic_seed.go wallet/mnemonic_seed_test.go
git commit -m "$(cat <<'EOF'
OB-56 derywacja ziarna portfela z 24-słowej frazy BIP39

Fraza -> ziarno BIP39 -> HKDF-SHA512 rozdzielone po nazwie schematu i roli.
Wyłącznie 24 słowa: 12 słów dałoby 128 bitów, czyli 2^64 pod Groverem.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Deterministyczny keygen pod strażą RNG (`crypto/oqs`)

Serce bezpieczeństwa całej zmiany. RNG liboqs jest globalny dla procesu, a `OQS_SIG_sign` z niego czerpie — deterministyczny RNG widziany przez podpisywanie oznacza powtórzone sole i odzyskanie klucza z podpisów w łańcuchu.

**Files:**
- Modify: `crypto/oqs/oqs.go:177-189` (`KeyEncapsulation.GenerateKeyPair`), `:400-412` (`Signature.GenerateKeyPair`), `:420-438` (`Signature.Sign`), blok importów `:11-15`
- Create: `crypto/oqs/deterministic.go`
- Test: `crypto/oqs/deterministic_test.go`

**Interfaces:**
- Consumes: `github.com/wonabru/qwid-node/crypto/oqs/rand` — `RandomBytesCustomAlgorithm(fun func([]byte, int)) error`, `RandomBytesSwitchAlgorithm(algName string) error`; `golang.org/x/crypto/hkdf` — `Expand(hash func() hash.Hash, pseudorandomKey, info []byte) io.Reader`
- Produces: `func (sig *Signature) GenerateKeyPairFromSeed(seed []byte) (pub []byte, drawn int, err error)`; niewyeksportowane `randMutex sync.Mutex` i `(sig *Signature) generateKeyPairUnlocked() ([]byte, error)`

- [ ] **Step 1: Napisz test, który nie przechodzi**

Utwórz `crypto/oqs/deterministic_test.go`:

```go
package oqs

import (
	"bytes"
	"sync"
	"testing"
)

const (
	testSigName  = "Falcon-512"
	testSigName2 = "MAYO-5"
)

func seedOf(b byte) []byte {
	return bytes.Repeat([]byte{b}, 64)
}

func TestGenerateKeyPairFromSeedIsDeterministic(t *testing.T) {
	var a, b Signature
	if err := a.Init(testSigName, nil); err != nil {
		t.Fatal(err)
	}
	defer a.Clean()
	if err := b.Init(testSigName, nil); err != nil {
		t.Fatal(err)
	}
	defer b.Clean()

	pubA, drawnA, err := a.GenerateKeyPairFromSeed(seedOf(0x11))
	if err != nil {
		t.Fatal(err)
	}
	pubB, drawnB, err := b.GenerateKeyPairFromSeed(seedOf(0x11))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pubA, pubB) {
		t.Fatal("to samo ziarno dało różne klucze publiczne")
	}
	if !bytes.Equal(a.ExportSecretKey(), b.ExportSecretKey()) {
		t.Fatal("to samo ziarno dało różne klucze prywatne")
	}
	if drawnA != drawnB {
		t.Fatalf("różna liczba pobranych bajtów: %d vs %d", drawnA, drawnB)
	}
}

// TestFalconDrawsExactlyFortyEightBytes pins liboqs behaviour. Falcon-512 keygen
// reads one 48-byte seed (pqclean.c:60) and expands it deterministically. If a
// liboqs upgrade changes that, every existing phrase would restore a different
// wallet — this test must fail loudly before that reaches users.
func TestFalconDrawsExactlyFortyEightBytes(t *testing.T) {
	var sig Signature
	if err := sig.Init(testSigName, nil); err != nil {
		t.Fatal(err)
	}
	defer sig.Clean()

	_, drawn, err := sig.GenerateKeyPairFromSeed(seedOf(0x22))
	if err != nil {
		t.Fatal(err)
	}
	if drawn != 48 {
		t.Fatalf("Falcon-512 pobrał %d bajtów z RNG, oczekiwano 48 — zachowanie liboqs się zmieniło", drawn)
	}
}

func TestMayoDrawsFixedByteCount(t *testing.T) {
	var a, b Signature
	if err := a.Init(testSigName2, nil); err != nil {
		t.Fatal(err)
	}
	defer a.Clean()
	if err := b.Init(testSigName2, nil); err != nil {
		t.Fatal(err)
	}
	defer b.Clean()

	_, drawnA, err := a.GenerateKeyPairFromSeed(seedOf(0x33))
	if err != nil {
		t.Fatal(err)
	}
	_, drawnB, err := b.GenerateKeyPairFromSeed(seedOf(0x44))
	if err != nil {
		t.Fatal(err)
	}
	if drawnA != drawnB {
		t.Fatalf("MAYO-5 pobrał różną liczbę bajtów dla różnych ziaren: %d vs %d", drawnA, drawnB)
	}
	if drawnA == 0 {
		t.Fatal("MAYO-5 nie pobrał żadnych bajtów — shim nie został zainstalowany")
	}
}

func TestDifferentSeedsGiveDifferentKeys(t *testing.T) {
	var a, b Signature
	if err := a.Init(testSigName, nil); err != nil {
		t.Fatal(err)
	}
	defer a.Clean()
	if err := b.Init(testSigName, nil); err != nil {
		t.Fatal(err)
	}
	defer b.Clean()

	pubA, _, err := a.GenerateKeyPairFromSeed(seedOf(0x55))
	if err != nil {
		t.Fatal(err)
	}
	pubB, _, err := b.GenerateKeyPairFromSeed(seedOf(0x66))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pubA, pubB) {
		t.Fatal("różne ziarna dały ten sam klucz")
	}
}

func TestGenerateKeyPairFromSeedRejectsShortSeed(t *testing.T) {
	var sig Signature
	if err := sig.Init(testSigName, nil); err != nil {
		t.Fatal(err)
	}
	defer sig.Clean()

	if _, _, err := sig.GenerateKeyPairFromSeed(make([]byte, 16)); err == nil {
		t.Fatal("oczekiwano błędu dla ziarna krótszego niż 32 bajty")
	}
}

// TestSigningStaysRandomAfterSeededKeygen is the regression test for the whole
// point of randMutex: if the deterministic RNG survived keygen, Falcon would
// reuse its 40-byte salt and two signatures published on-chain would reveal the
// private key.
func TestSigningStaysRandomAfterSeededKeygen(t *testing.T) {
	var sig Signature
	if err := sig.Init(testSigName, nil); err != nil {
		t.Fatal(err)
	}
	defer sig.Clean()

	if _, _, err := sig.GenerateKeyPairFromSeed(seedOf(0x77)); err != nil {
		t.Fatal(err)
	}

	msg := []byte("qwid")
	s1, err := sig.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := sig.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s1, s2) {
		t.Fatal("dwa podpisy tej samej wiadomości są identyczne — deterministyczny RNG " +
			"przeciekł do podpisywania; powtórzona sól ujawnia klucz prywatny")
	}
}

// TestConcurrentSigningStaysRandom runs the same guarantee under -race with
// keygen and signing fighting for the global RNG.
func TestConcurrentSigningStaysRandom(t *testing.T) {
	var signer Signature
	if err := signer.Init(testSigName, nil); err != nil {
		t.Fatal(err)
	}
	defer signer.Clean()
	if _, err := signer.GenerateKeyPair(); err != nil {
		t.Fatal(err)
	}

	msg := []byte("qwid")
	var mu sync.Mutex
	seen := map[string]bool{}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := signer.Sign(msg)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[string(s)] {
				t.Error("powtórzony podpis przy równoległym generowaniu kluczy z ziarna")
			}
			seen[string(s)] = true
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			var s Signature
			if err := s.Init(testSigName, nil); err != nil {
				t.Error(err)
				return
			}
			defer s.Clean()
			if _, _, err := s.GenerateKeyPairFromSeed(seedOf(byte(n))); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
}
```

- [ ] **Step 2: Uruchom test i potwierdź, że nie przechodzi**

```bash
$GO test ./crypto/oqs/ -run TestGenerateKeyPairFromSeed -v
```

Oczekiwane: błąd kompilacji `sig.GenerateKeyPairFromSeed undefined`.

- [ ] **Step 3: Dodaj mutex i rozbij `GenerateKeyPair` w `crypto/oqs/oqs.go`**

W bloku importów (`crypto/oqs/oqs.go:11-15`) dopisz `"sync"`:

```go
import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)
```

Pod blokiem importów dodaj:

```go
// randMutex serializes every liboqs call that consumes randomness. It exists so
// GenerateKeyPairFromSeed can install a deterministic RNG — which is global to
// the process — without any concurrent signing observing it. A signature that
// reused its salt would let anyone recover the private key from two signatures
// published on-chain. OQS_SIG_verify draws no randomness and is deliberately
// left unguarded, so block verification keeps its full parallelism.
var randMutex sync.Mutex
```

Zamień `Signature.GenerateKeyPair` (`:400-412`) na parę zamek/rdzeń:

```go
func (sig *Signature) GenerateKeyPair() ([]byte, error) {
	randMutex.Lock()
	defer randMutex.Unlock()
	return sig.generateKeyPairUnlocked()
}

// generateKeyPairUnlocked is the body of GenerateKeyPair. The caller must hold
// randMutex.
func (sig *Signature) generateKeyPairUnlocked() ([]byte, error) {
	publicKey := make([]byte, sig.algDetails.LengthPublicKey)
	sig.secretKey = make([]byte, sig.algDetails.LengthSecretKey)

	rv := C.OQS_SIG_keypair(sig.sig,
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
		(*C.uint8_t)(unsafe.Pointer(&sig.secretKey[0])))
	if rv != C.OQS_SUCCESS {
		return nil, errors.New("can not generate keypair")
	}

	return publicKey, nil
}
```

W `Signature.Sign` (`:420`) wstaw blokadę po walidacji długości klucza, tuż przed `signature := make(...)`:

```go
	randMutex.Lock()
	defer randMutex.Unlock()

	signature := make([]byte, sig.algDetails.MaxLengthSignature)
```

W `KeyEncapsulation.GenerateKeyPair` (`:177`) wstaw blokadę jako pierwsze dwie linie ciała:

```go
func (kem *KeyEncapsulation) GenerateKeyPair() ([]byte, error) {
	randMutex.Lock()
	defer randMutex.Unlock()

	publicKey := make([]byte, kem.algDetails.LengthPublicKey)
```

- [ ] **Step 4: Napisz `crypto/oqs/deterministic.go`**

```go
package oqs

import (
	"crypto/sha512"
	"errors"
	"io"

	oqsrand "github.com/wonabru/qwid-node/crypto/oqs/rand"
	"github.com/wonabru/qwid-node/logger"
	"golang.org/x/crypto/hkdf"
)

// detKeygenInfo separates the keygen byte stream from any other use of the same
// per-key seed. Changing it invalidates every existing wallet — it is pinned by
// the known-answer test.
const detKeygenInfo = "qwid-oqs-keygen-v1"

// minSeedLength is the smallest seed accepted for deterministic keygen. Anything
// shorter would cap key security below the scheme's own level.
const minSeedLength = 32

// GenerateKeyPairFromSeed generates the key pair that seed determines, instead of
// drawing from the system RNG. It returns the public key and how many bytes
// liboqs pulled from the deterministic stream; the byte count is what lets a test
// pin liboqs' behaviour, because a change there would make every existing
// recovery phrase restore a different wallet.
//
// The deterministic RNG is global to the liboqs process, so it is installed and
// removed while holding randMutex — the same lock Sign holds. Signing therefore
// can never observe it, and Falcon's per-signature salt always comes from the
// system CSPRNG.
func (sig *Signature) GenerateKeyPairFromSeed(seed []byte) ([]byte, int, error) {
	if len(seed) < minSeedLength {
		return nil, 0, errors.New("seed must be at least 32 bytes for deterministic keygen")
	}

	stream := hkdf.Expand(sha512.New, seed, []byte(detKeygenInfo))
	drawn := 0
	var streamErr error

	randMutex.Lock()
	defer randMutex.Unlock()

	if err := oqsrand.RandomBytesCustomAlgorithm(func(out []byte, n int) {
		if n > len(out) {
			n = len(out)
		}
		if _, err := io.ReadFull(stream, out[:n]); err != nil {
			if streamErr == nil {
				streamErr = err
			}
			return
		}
		drawn += n
	}); err != nil {
		return nil, 0, err
	}
	// Runs before the randMutex unlock above: defers are LIFO, so the system RNG
	// is back in place while the lock still keeps signers out. Also covers a panic
	// from inside liboqs.
	defer restoreSystemRNG()

	pub, err := sig.generateKeyPairUnlocked()
	if err != nil {
		return nil, drawn, err
	}
	if streamErr != nil {
		return nil, drawn, streamErr
	}
	return pub, drawn, nil
}

// restoreSystemRNG puts liboqs back on the system CSPRNG. Failing to restore it
// would leave the node signing with a deterministic RNG, which publishes the
// private key through repeated salts — halting is the lesser harm.
func restoreSystemRNG() {
	if err := oqsrand.RandomBytesSwitchAlgorithm("system"); err != nil {
		logger.GetLogger().Fatal("cannot restore the system RNG after deterministic keygen; "+
			"continuing would sign with a predictable salt and leak the private key: ", err)
	}
}
```

- [ ] **Step 5: Uruchom testy, także pod detektorem wyścigów**

```bash
$GO test ./crypto/oqs/ -run 'TestGenerateKeyPairFromSeed|TestFalconDraws|TestMayoDraws|TestDifferentSeeds|TestSigningStaysRandom' -v
$GO test ./crypto/oqs/ -run 'TestConcurrentSigningStaysRandom' -race -v
```

Oczekiwane: wszystkie PASS, `TestFalconDrawsExactlyFortyEightBytes` potwierdza 48 bajtów.

- [ ] **Step 6: Sprawdź, że reszta projektu żyje**

```bash
$GO build ./... && $GO test ./crypto/... ./wallet/ ./blocks/
```

- [ ] **Step 7: Commit**

```bash
git add crypto/oqs/oqs.go crypto/oqs/deterministic.go crypto/oqs/deterministic_test.go
git commit -m "$(cat <<'EOF'
OB-56 deterministyczne generowanie kluczy z ziarna pod strażą RNG

RNG liboqs jest globalny dla procesu, a OQS_SIG_sign z niego czerpie. randMutex
trzymany przez Sign i oba warianty keygenu gwarantuje, że podpisywanie nigdy nie
zobaczy deterministycznego RNG — inaczej powtórzona 40-bajtowa sól Falcona
ujawniłaby klucz prywatny z dwóch podpisów widocznych w blockchainie.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Fraza w portfelu i generowanie kont z ziarna (`wallet/wallet.go`)

**Files:**
- Modify: `wallet/wallet.go` — struktura `Wallet` (`:50-67`), `Wipe` (`:123-141`), `GenerateNewAccount` (`:256-295`), `StoreJSON` (`:529`), `loadWalletFromStruct` (`:647`)
- Test: `wallet/seed_persistence_test.go`

**Interfaces:**
- Consumes: Task 1 — `SeedFromMnemonic`, `DeriveKeySeed`, `ZeroBytes`; Task 2 — `(*oqs.Signature).GenerateKeyPairFromSeed`
- Produces:
  - pole `EncryptedMnemonic []byte \`json:"encrypted_mnemonic,omitempty"\`` w `Wallet`
  - niewyeksportowane `seed []byte` w `Wallet`
  - `func (w *Wallet) SetMnemonic(mnemonic []byte) error`
  - `func (w *Wallet) HasSeed() bool`
  - `func GenerateNewAccountFromSeed(w Wallet, sigName string, primary bool) (Account, error)`

- [ ] **Step 1: Napisz test, który nie przechodzi**

Utwórz `wallet/seed_persistence_test.go`:

```go
package wallet

import (
	"strings"
	"testing"

	"github.com/wonabru/qwid-node/common"
)

// newSeedTestWallet builds a wallet whose files land in a throwaway directory.
// Named to avoid colliding with the pre-existing newTestWallet(password string)
// in wallet/encrypt_test.go.
func newSeedTestWallet(t *testing.T, number uint8) *Wallet {
	t.Helper()
	w := EmptyWallet(number, common.SigName(), common.SigName2())
	w.HomePath = t.TempDir()
	w.SetPassword("test-password-123")
	w.Iv = GenerateNewIv()
	return &w
}

func fillAccountsFromSeed(t *testing.T, w *Wallet) {
	t.Helper()
	acc, err := GenerateNewAccountFromSeed(*w, w.SigName, true)
	if err != nil {
		t.Fatal(err)
	}
	w.MainAddress = acc.Address
	acc.PublicKey.MainAddress = w.MainAddress
	w.Account1 = acc

	acc2, err := GenerateNewAccountFromSeed(*w, w.SigName2, false)
	if err != nil {
		t.Fatal(err)
	}
	w.Account2 = acc2
}

func TestSetMnemonicRejectsInvalidPhrase(t *testing.T) {
	w := newSeedTestWallet(t, 200)
	if err := w.SetMnemonic([]byte("not a real phrase")); err == nil {
		t.Fatal("oczekiwano błędu dla nieprawidłowej frazy")
	}
	if w.HasSeed() {
		t.Fatal("portfel ma ziarno mimo odrzuconej frazy")
	}
}

func TestSeededWalletIsReproducibleFromPhrase(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	w1 := newSeedTestWallet(t, 201)
	if err := w1.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w1)

	w2 := newSeedTestWallet(t, 201)
	if err := w2.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w2)

	if w1.MainAddress.GetHex() != w2.MainAddress.GetHex() {
		t.Fatalf("ta sama fraza dała różne adresy: %s vs %s",
			w1.MainAddress.GetHex(), w2.MainAddress.GetHex())
	}
	if w1.Account2.Address.GetHex() != w2.Account2.Address.GetHex() {
		t.Fatal("ta sama fraza dała różne adresy drugiego konta")
	}
}

func TestDifferentPhrasesGiveDifferentWallets(t *testing.T) {
	m1, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	m2, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	w1 := newSeedTestWallet(t, 202)
	if err := w1.SetMnemonic(m1); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w1)

	w2 := newSeedTestWallet(t, 202)
	if err := w2.SetMnemonic(m2); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w2)

	if w1.MainAddress.GetHex() == w2.MainAddress.GetHex() {
		t.Fatal("różne frazy dały ten sam adres")
	}
}

func TestMnemonicSurvivesStoreAndLoad(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 203)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}
	if len(w.EncryptedMnemonic) == 0 {
		t.Fatal("StoreJSON nie zapisał zaszyfrowanej frazy")
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 203, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.HasSeed() {
		t.Fatal("wczytany portfel nie ma ziarna")
	}
	if loaded.MainAddress.GetHex() != w.MainAddress.GetHex() {
		t.Fatal("adres zmienił się po zapisie i odczycie")
	}
}

func TestLegacyWalletLoadsWithoutSeed(t *testing.T) {
	w := newSeedTestWallet(t, 204)
	acc, err := GenerateNewAccount(*w, w.SigName)
	if err != nil {
		t.Fatal(err)
	}
	w.MainAddress = acc.Address
	w.Account1 = acc
	acc2, err := GenerateNewAccount(*w, w.SigName2)
	if err != nil {
		t.Fatal(err)
	}
	w.Account2 = acc2

	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	data, err := readWalletFile(t, w.HomePath, 204)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(data, "encrypted_mnemonic") {
		t.Fatal("portfel bez frazy zapisał puste pole encrypted_mnemonic — brakuje omitempty")
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 204, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("portfel starego typu nie wczytał się: %v", err)
	}
	if loaded.HasSeed() {
		t.Fatal("portfel starego typu zgłasza posiadanie ziarna")
	}
	if _, err := loaded.Sign([]byte("qwid"), true); err != nil {
		t.Fatalf("portfel starego typu nie podpisuje: %v", err)
	}
}

func TestWipeClearsSeed(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 205)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)

	w.Wipe()
	if w.HasSeed() {
		t.Fatal("Wipe nie wyczyścił ziarna")
	}
}
```

Dopisz na końcu tego samego pliku pomocnika:

```go
func readWalletFile(t *testing.T, dir string, number uint8) (string, error) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "wallet"+strconv.Itoa(int(number))+".json"))
	return string(b), err
}
```

i uzupełnij importy pliku testowego o `"os"`, `"path/filepath"`, `"strconv"`.

- [ ] **Step 2: Uruchom test i potwierdź, że nie przechodzi**

```bash
$GO test ./wallet/ -run 'TestSetMnemonic|TestSeededWallet|TestDifferentPhrases|TestMnemonicSurvives|TestLegacyWallet|TestWipeClearsSeed' -v
```

Oczekiwane: błąd kompilacji `w.SetMnemonic undefined`.

- [ ] **Step 3: Rozszerz strukturę `Wallet` (`wallet/wallet.go:50`)**

Do struktury dopisz dwa pola tuż pod `passwordBytes`:

```go
	// seed is the 64-byte BIP39 seed derived from the recovery phrase. Present
	// only while the wallet is unlocked; Wipe() zeroes it.
	seed []byte
	// EncryptedMnemonic holds the recovery phrase under the same AES-256-GCM /
	// Argon2id key as the secret keys. The phrase is stored rather than the seed
	// because PBKDF2 is one-way: from a seed the words cannot be shown again.
	// omitempty keeps pre-existing wallet files byte-identical.
	EncryptedMnemonic []byte `json:"encrypted_mnemonic,omitempty"`
```

- [ ] **Step 4: Dodaj metody ziarna i generowanie kont z ziarna**

Wstaw nad `GenerateNewAccount` (`wallet/wallet.go:256`):

```go
// SetMnemonic validates a recovery phrase, derives the wallet seed from it and
// keeps the phrase encrypted so it can be shown again later. Requires the wallet
// password to be set first, since the phrase is encrypted with the key derived
// from it.
func (w *Wallet) SetMnemonic(mnemonic []byte) error {
	if len(w.passwordBytes) == 0 {
		return fmt.Errorf("set the wallet password before the recovery phrase")
	}
	seed, err := SeedFromMnemonic(mnemonic)
	if err != nil {
		return err
	}
	enc, err := w.encrypt(mnemonic)
	if err != nil {
		return err
	}
	w.seed = seed
	w.EncryptedMnemonic = enc
	return nil
}

// HasSeed reports whether this wallet can derive keys from a recovery phrase.
// Wallets created before this feature return false and keep their previous,
// random key generation.
func (w *Wallet) HasSeed() bool {
	return len(w.seed) > 0
}

// GenerateNewAccountFromSeed creates the account that this wallet's recovery
// phrase determines for one signature scheme and role. Without a seed it falls
// back to GenerateNewAccount, so pre-existing wallets are unaffected.
func GenerateNewAccountFromSeed(w Wallet, sigName string, primary bool) (Account, error) {
	if !w.HasSeed() {
		return GenerateNewAccount(w, sigName)
	}
	if len(w.password) < 1 {
		return Account{}, fmt.Errorf("password cannot be empty")
	}

	var signer oqs.Signature
	if err := signer.Init(sigName, nil); err != nil {
		return Account{}, err
	}

	keySeed := DeriveKeySeed(w.seed, sigName, primary)
	defer ZeroBytes(keySeed)

	pubKey, drawn, err := signer.GenerateKeyPairFromSeed(keySeed)
	if err != nil {
		return Account{}, err
	}
	logger.GetLogger().Printf("derived %s key from the recovery phrase (%d RNG bytes consumed)", sigName, drawn)

	acc := EmptyAccount()
	if err := acc.PublicKey.Init(pubKey, w.MainAddress); err != nil {
		return Account{}, err
	}
	acc.Address = acc.PublicKey.GetAddress()

	if err := acc.secretKey.Init(signer.ExportSecretKey(), acc.Address, false); err != nil {
		return Account{}, err
	}
	acc.signer = signer

	se, err := w.encrypt(acc.secretKey.GetBytes())
	if err != nil {
		logger.GetLogger().Println(err)
		return Account{}, err
	}
	acc.EncryptedSecretKey = make([]byte, len(se))
	copy(acc.EncryptedSecretKey, se)

	return acc, nil
}
```

- [ ] **Step 5: Zeruj ziarno w `Wipe` (`wallet/wallet.go:123`)**

Zaraz po pętli zerującej `w.passwordBytes`, przed `w.password = nil`:

```go
	for i := range w.seed {
		w.seed[i] = 0
	}
	w.seed = nil
```

- [ ] **Step 6: Odszyfruj frazę przy ładowaniu (`wallet/wallet.go:647`)**

W `loadWalletFromStruct` przenieś `w.SetPassword(password)` na sam początek funkcji, przed oba bloki `if !common.IsPaused...`, i zaraz pod nim dodaj:

```go
	w.SetPassword(password)

	// Recover the seed before anything can need it: the scheme-change branches
	// below generate keys, and with a seed those must be derived, not random.
	if len(w.EncryptedMnemonic) > 0 {
		mnemonic, err := w.decrypt(w.EncryptedMnemonic)
		if err != nil {
			logger.GetLogger().Println("cannot decrypt the recovery phrase, continuing without a seed:", err)
		} else {
			seed, serr := SeedFromMnemonic(mnemonic)
			ZeroBytes(mnemonic)
			if serr != nil {
				logger.GetLogger().Println("stored recovery phrase is not valid, continuing without a seed:", serr)
			} else {
				w.seed = seed
			}
		}
	}
```

Usuń dawne wywołanie `w.SetPassword(password)` z jego poprzedniego miejsca (po blokach zmiany schematu). Następnie w obu blokach zamień `GenerateNewAccount(*w, sigName)` na `GenerateNewAccountFromSeed(*w, sigName, true)` i `GenerateNewAccount(*w, sigName2)` na `GenerateNewAccountFromSeed(*w, sigName2, false)`.

- [ ] **Step 7: Zapisz zaszyfrowaną frazę w `StoreJSON` (`wallet/wallet.go:529`)**

Bezpośrednio przed `w.normalizeAccountRoles()` dodaj:

```go
	// Re-encrypt the phrase under the current password so ChangePassword leaves a
	// file whose phrase opens with the new one.
	if w.HasSeed() && len(w.EncryptedMnemonic) > 0 {
		mnemonic, err := w.decrypt(w.EncryptedMnemonic)
		if err == nil {
			enc, eerr := w.encrypt(mnemonic)
			ZeroBytes(mnemonic)
			if eerr != nil {
				return eerr
			}
			w.EncryptedMnemonic = enc
		}
	}
```

- [ ] **Step 8: Uruchom testy**

```bash
$GO test ./wallet/ -v
```

Oczekiwane: wszystkie PASS, w tym `TestLegacyWalletLoadsWithoutSeed`.

- [ ] **Step 9: Commit**

```bash
git add wallet/wallet.go wallet/seed_persistence_test.go
git commit -m "$(cat <<'EOF'
OB-56 fraza w pliku portfela i generowanie kont z ziarna

Przechowujemy frazę, nie ziarno: PBKDF2 jest jednokierunkowe, więc z ziarna nie
dałoby się pokazać słów ponownie. Portfele bez pola encrypted_mnemonic ładują
się i podpisują dokładnie jak dotychczas.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Zmiana schematu szyfrowania korzysta z ziarna

Bez tego mnemonic przestaje wystarczać do odtworzenia portfela po pierwszym głosowaniu w łańcuchu.

**Files:**
- Modify: `wallet/wallet.go:297-345` (`AddNewEncryptionToActiveWallet`)
- Test: `wallet/seed_encryption_change_test.go`

**Interfaces:**
- Consumes: Task 3 — `HasSeed`, `DeriveKeySeed`, `GenerateKeyPairFromSeed`
- Produces: brak nowych symboli; zmiana zachowania `AddNewEncryptionToActiveWallet`

- [ ] **Step 1: Napisz test, który nie przechodzi**

Utwórz `wallet/seed_encryption_change_test.go`:

```go
package wallet

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
)

// TestSchemeChangeIsReproducibleFromPhrase: when the chain votes in a new
// scheme, the node generates that key unattended. If it were random, the
// recovery phrase would stop being enough to restore the wallet.
func TestSchemeChangeIsReproducibleFromPhrase(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	newScheme := common.SigName2()

	w1 := newSeedTestWallet(t, 210)
	if err := w1.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w1)
	if err := w1.AddNewEncryptionToActiveWallet(newScheme, true); err != nil {
		t.Fatal(err)
	}

	w2 := newSeedTestWallet(t, 210)
	if err := w2.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w2)
	if err := w2.AddNewEncryptionToActiveWallet(newScheme, true); err != nil {
		t.Fatal(err)
	}

	if w1.Account1.Address.GetHex() != w2.Account1.Address.GetHex() {
		t.Fatalf("klucz dla nowego schematu nie jest odtwarzalny z frazy: %s vs %s",
			w1.Account1.Address.GetHex(), w2.Account1.Address.GetHex())
	}
}

// TestSchemeChangeStaysRandomWithoutPhrase keeps pre-existing wallets on their
// previous behaviour.
func TestSchemeChangeStaysRandomWithoutPhrase(t *testing.T) {
	newScheme := common.SigName2()

	addr := func() string {
		w := newSeedTestWallet(t, 211)
		acc, err := GenerateNewAccount(*w, w.SigName)
		if err != nil {
			t.Fatal(err)
		}
		w.MainAddress = acc.Address
		w.Account1 = acc
		acc2, err := GenerateNewAccount(*w, w.SigName2)
		if err != nil {
			t.Fatal(err)
		}
		w.Account2 = acc2
		if err := w.AddNewEncryptionToActiveWallet(newScheme, true); err != nil {
			t.Fatal(err)
		}
		return w.Account1.Address.GetHex()
	}

	if addr() == addr() {
		t.Fatal("portfel bez frazy dał ten sam klucz dwa razy — generowanie przestało być losowe")
	}
}
```

- [ ] **Step 2: Uruchom test i potwierdź, że nie przechodzi**

```bash
$GO test ./wallet/ -run TestSchemeChange -v
```

Oczekiwane: `TestSchemeChangeIsReproducibleFromPhrase` FAIL — dwa różne adresy.

- [ ] **Step 3: Wyprowadź klucz z ziarna w `AddNewEncryptionToActiveWallet`**

W `wallet/wallet.go` zamień blok generowania klucza (`:306-313`):

```go
	err := signer.Init(sigName, nil)
	if err != nil {
		return err
	}
	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		return err
	}
```

na:

```go
	err := signer.Init(sigName, nil)
	if err != nil {
		return err
	}
	var pubKey []byte
	if w.HasSeed() {
		keySeed := DeriveKeySeed(w.seed, sigName, primary)
		defer ZeroBytes(keySeed)
		var drawn int
		pubKey, drawn, err = signer.GenerateKeyPairFromSeed(keySeed)
		if err != nil {
			return err
		}
		logger.GetLogger().Printf("derived the %s key for the new scheme from the recovery phrase (%d RNG bytes)", sigName, drawn)
	} else {
		pubKey, err = signer.GenerateKeyPair()
		if err != nil {
			return err
		}
		logger.GetLogger().Printf("WARNING: generated a random %s key — this wallet has no recovery phrase, "+
			"so the new key cannot be restored from one; back up the wallet file", sigName)
	}
```

- [ ] **Step 4: Uruchom testy**

```bash
$GO test ./wallet/ -run TestSchemeChange -v && $GO test ./wallet/
```

Oczekiwane: wszystkie PASS.

- [ ] **Step 5: Commit**

```bash
git add wallet/wallet.go wallet/seed_encryption_change_test.go
git commit -m "$(cat <<'EOF'
OB-56 klucz dla nowego schematu wyprowadzany z frazy

Po głosowaniu nad zmianą szyfrowania węzeł generuje klucz bez nadzoru. Losowy
klucz sprawiłby, że fraza przestaje wystarczać do odtworzenia portfela.
Portfele bez frazy zachowują dotychczasowe losowe generowanie z ostrzeżeniem.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Nowa semantyka `GetMnemonicWords` i `RestoreSecretKeyFromMnemonic`

**Files:**
- Modify: `wallet/wallet.go:431-504`
- Modify: `wallet/mnemonic_test.go` (istniejący test opisuje starą, odwróconą semantykę)

**Interfaces:**
- Consumes: Task 3 — `EncryptedMnemonic`, `HasSeed`, `SetMnemonic`, `GenerateNewAccountFromSeed`
- Produces:
  - `func (w *Wallet) GetMnemonicWords(primary bool) (string, error)` — sygnatura bez zmian, zachowanie nowe
  - `func (w *Wallet) RestoreSecretKeyFromMnemonic(mnemonic string, primary bool) error` — sygnatura bez zmian, zachowanie nowe

- [ ] **Step 1: Napisz test, który nie przechodzi**

Zastąp całą treść `wallet/mnemonic_test.go`:

```go
package wallet

import (
	"strings"
	"testing"
)

// TestGetMnemonicWordsReturnsThePhraseThatCreatedTheWallet replaces the old
// CW-M2 behaviour. The phrase is no longer an encoding of the secret key — which
// is impossible for post-quantum keys — but the input the wallet was built from.
func TestGetMnemonicWordsReturnsThePhraseThatCreatedTheWallet(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 220)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)

	got, err := w.GetMnemonicWords(true)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(mnemonic) {
		t.Fatalf("zwrócona fraza różni się od podanej przy tworzeniu")
	}
	if n := len(strings.Fields(got)); n != MnemonicWordCount {
		t.Fatalf("liczba słów = %d, oczekiwano %d", n, MnemonicWordCount)
	}
}

// TestGetMnemonicWordsOnLegacyWalletExplainsWhy: a wallet created before this
// feature has no phrase and never can — the caller must be told to back up the
// file instead.
func TestGetMnemonicWordsOnLegacyWalletExplainsWhy(t *testing.T) {
	w := newSeedTestWallet(t, 221)
	_, err := w.GetMnemonicWords(true)
	if err == nil {
		t.Fatal("oczekiwano błędu dla portfela bez frazy")
	}
	if !strings.Contains(err.Error(), "wallet-file") {
		t.Fatalf("komunikat %q nie kieruje do kopii pliku portfela", err.Error())
	}
}

func TestRestoreFromMnemonicRebuildsTheSameKeys(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	original := newSeedTestWallet(t, 222)
	if err := original.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, original)

	restored := newSeedTestWallet(t, 222)
	if err := restored.RestoreSecretKeyFromMnemonic(string(mnemonic), true); err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreSecretKeyFromMnemonic(string(mnemonic), false); err != nil {
		t.Fatal(err)
	}

	if restored.Account1.Address.GetHex() != original.Account1.Address.GetHex() {
		t.Fatal("odtworzony klucz podstawowy ma inny adres")
	}
	if restored.Account2.Address.GetHex() != original.Account2.Address.GetHex() {
		t.Fatal("odtworzony klucz dodatkowy ma inny adres")
	}

	sig, err := restored.Sign([]byte("qwid"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify([]byte("qwid"), sig.GetBytes(), original.Account1.PublicKey.GetBytes(),
		original.SigName, original.SigName2, false, false) {
		t.Fatal("podpis odtworzonym kluczem nie weryfikuje się oryginalnym kluczem publicznym")
	}
}

func TestRestoreFromMnemonicRejectsBadPhrase(t *testing.T) {
	w := newSeedTestWallet(t, 223)
	if err := w.RestoreSecretKeyFromMnemonic("abandon abandon abandon", true); err == nil {
		t.Fatal("oczekiwano błędu dla frazy o złej długości")
	}
}
```

- [ ] **Step 2: Uruchom test i potwierdź, że nie przechodzi**

```bash
$GO test ./wallet/ -run 'TestGetMnemonicWords|TestRestoreFromMnemonic' -v
```

Oczekiwane: FAIL — stara implementacja próbuje zakodować klucz prywatny.

- [ ] **Step 3: Zastąp obie funkcje w `wallet/wallet.go:431-504`**

```go
// GetMnemonicWords returns the recovery phrase this wallet was created from.
//
// Note the direction: the phrase is the input the keys were derived from, not an
// encoding of a key. Encoding a post-quantum secret key as a phrase is
// impossible (Falcon-512 is ~1281 bytes against BIP39's 64), which is why
// wallets created before this feature have no phrase and never can (CW-M2).
func (w *Wallet) GetMnemonicWords(primary bool) (string, error) {
	if len(w.EncryptedMnemonic) == 0 {
		return "", fmt.Errorf("this wallet was created without a recovery phrase; " +
			"use the encrypted wallet-file backup instead")
	}
	if len(w.passwordBytes) == 0 {
		return "", fmt.Errorf("you need load wallet first")
	}
	mnemonic, err := w.decrypt(w.EncryptedMnemonic)
	if err != nil {
		return "", fmt.Errorf("cannot decrypt the recovery phrase: %w", err)
	}
	// The phrase covers every scheme and both roles, so `primary` does not select
	// between two phrases — it is kept only so existing callers still compile.
	_ = primary
	return string(mnemonic), nil
}

// RestoreSecretKeyFromMnemonic rebuilds one of the wallet's keys from a recovery
// phrase. The key is derived, not unpacked: the same phrase always yields the
// same key for a given scheme and role.
func (w *Wallet) RestoreSecretKeyFromMnemonic(mnemonic string, primary bool) error {
	if err := w.SetMnemonic([]byte(mnemonic)); err != nil {
		return err
	}
	sigName := w.SigName
	if !primary {
		sigName = w.SigName2
	}
	acc, err := GenerateNewAccountFromSeed(*w, sigName, primary)
	if err != nil {
		return err
	}
	if primary {
		w.Account1 = acc
		if w.MainAddress.GetHex() == (common.Address{}).GetHex() {
			w.MainAddress = acc.Address
		}
	} else {
		w.Account2 = acc
	}
	return nil
}
```

- [ ] **Step 4: Uruchom testy**

```bash
$GO test ./wallet/ -v
```

Oczekiwane: wszystkie PASS.

- [ ] **Step 5: Commit**

```bash
git add wallet/wallet.go wallet/mnemonic_test.go
git commit -m "$(cat <<'EOF'
OB-56 odwrócenie semantyki funkcji frazy

GetMnemonicWords zwraca frazę, z której portfel powstał, zamiast próbować
zakodować klucz prywatny — co dla kluczy post-kwantowych jest niewykonalne.
RestoreSecretKeyFromMnemonic wyprowadza klucz z frazy zamiast wpychać jej bajty
w miejsce klucza.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Tryby „utwórz" i „odtwórz" w `cmd/generateNewWallet`

**Files:**
- Modify: `cmd/generateNewWallet/main.go` (kod pomocniczy dopisujemy tutaj — pakiet musi zostać jednoplikowy, patrz Global Constraints)
- Test: `cmd/generateNewWallet/prompt_test.go`

**Interfaces:**
- Consumes: Task 1 — `NewMnemonic24`; Task 3 — `SetMnemonic`, `GenerateNewAccountFromSeed`
- Produces: `func confirmPositions(seed64 [8]byte, wordCount int) []int`, `func checkConfirmation(mnemonic string, positions []int, answers []string) error`

- [ ] **Step 1: Napisz test, który nie przechodzi**

Utwórz `cmd/generateNewWallet/prompt_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

func TestConfirmPositionsAreDistinctAndInRange(t *testing.T) {
	pos := confirmPositions([8]byte{1, 2, 3, 4, 5, 6, 7, 8}, 24)
	if len(pos) != 3 {
		t.Fatalf("liczba pozycji = %d, oczekiwano 3", len(pos))
	}
	seen := map[int]bool{}
	for _, p := range pos {
		if p < 1 || p > 24 {
			t.Fatalf("pozycja %d poza zakresem 1..24", p)
		}
		if seen[p] {
			t.Fatalf("pozycja %d powtórzona", p)
		}
		seen[p] = true
	}
}

func TestCheckConfirmationAcceptsCorrectWords(t *testing.T) {
	mnemonic := strings.Join(strings.Fields(strings.Repeat("abandon ", 23)+"art"), " ")
	words := strings.Fields(mnemonic)
	positions := []int{1, 12, 24}
	answers := []string{words[0], words[11], words[23]}

	if err := checkConfirmation(mnemonic, positions, answers); err != nil {
		t.Fatalf("poprawne słowa odrzucone: %v", err)
	}
}

func TestCheckConfirmationRejectsWrongWord(t *testing.T) {
	mnemonic := strings.Join(strings.Fields(strings.Repeat("abandon ", 23)+"art"), " ")
	positions := []int{1, 12, 24}
	answers := []string{"abandon", "abandon", "abandon"} // pozycja 24 to "art"

	err := checkConfirmation(mnemonic, positions, answers)
	if err == nil {
		t.Fatal("oczekiwano błędu dla błędnego słowa")
	}
	if !strings.Contains(err.Error(), "24") {
		t.Fatalf("komunikat %q nie wskazuje błędnej pozycji", err.Error())
	}
}

func TestCheckConfirmationIsCaseAndSpaceInsensitive(t *testing.T) {
	mnemonic := strings.Join(strings.Fields(strings.Repeat("abandon ", 23)+"art"), " ")
	if err := checkConfirmation(mnemonic, []int{24}, []string{"  ART "}); err != nil {
		t.Fatalf("odrzucono poprawne słowo z inną wielkością liter i spacjami: %v", err)
	}
}
```

- [ ] **Step 2: Uruchom test i potwierdź, że nie przechodzi**

```bash
$GO test ./cmd/generateNewWallet/ -v
```

Oczekiwane: błąd kompilacji `undefined: confirmPositions`.

- [ ] **Step 3: Dopisz pomocniki potwierdzania na końcu `cmd/generateNewWallet/main.go`**

Uzupełnij blok importów `main.go` o `"crypto/rand"`, `"encoding/binary"`, `"bufio"` i `"strings"` (`fmt` i `strconv` już tam są), a na końcu pliku dopisz:

```go
// confirmWordCount is how many words the operator must type back before the
// wallet is created. Three is enough to catch "I'll write it down later" without
// making the prompt tedious.
const confirmWordCount = 3

// confirmPositions picks distinct 1-based word positions to ask about, derived
// from seed64 so the choice is unpredictable but the function stays testable.
func confirmPositions(seed64 [8]byte, wordCount int) []int {
	n := binary.BigEndian.Uint64(seed64[:])
	chosen := map[int]bool{}
	out := make([]int, 0, confirmWordCount)
	for len(out) < confirmWordCount {
		p := int(n%uint64(wordCount)) + 1
		n = n/uint64(wordCount) + 1
		if chosen[p] {
			continue
		}
		chosen[p] = true
		out = append(out, p)
	}
	return out
}

// randomConfirmPositions is confirmPositions seeded from the system CSPRNG.
func randomConfirmPositions(wordCount int) ([]int, error) {
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return confirmPositions(seed, wordCount), nil
}

// checkConfirmation verifies the operator typed back the right words. Comparison
// ignores surrounding space and letter case; BIP39 words are lowercase ASCII.
func checkConfirmation(mnemonic string, positions []int, answers []string) error {
	words := strings.Fields(mnemonic)
	if len(positions) != len(answers) {
		return fmt.Errorf("oczekiwano %d odpowiedzi, podano %d", len(positions), len(answers))
	}
	for i, p := range positions {
		if p < 1 || p > len(words) {
			return fmt.Errorf("pozycja %d poza zakresem", p)
		}
		got := strings.ToLower(strings.TrimSpace(answers[i]))
		if got != words[p-1] {
			return fmt.Errorf("słowo na pozycji %d nie zgadza się", p)
		}
	}
	return nil
}
```

- [ ] **Step 4: Uruchom testy**

```bash
$GO test ./cmd/generateNewWallet/ -v
```

Oczekiwane: wszystkie PASS.

- [ ] **Step 5: Wepnij tryby w `cmd/generateNewWallet/main.go`**

Po wczytaniu hasła (`main.go:36-39`), przed `w := wallet.EmptyWallet(...)`, wstaw wybór trybu i obsługę frazy:

```go
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\n[1] utwórz nowy portfel  [2] odtwórz z frazy 24 słów\nWybór [1]: ")
	mode, _ := reader.ReadString('\n')
	mode = strings.TrimSpace(mode)

	var mnemonic []byte
	if mode == "2" {
		fmt.Print("Wpisz frazę (24 słowa oddzielone spacjami): ")
		line, err := reader.ReadString('\n')
		if err != nil {
			logger.GetLogger().Fatal(err)
		}
		mnemonic = []byte(strings.TrimSpace(line))
		if _, err := wallet.SeedFromMnemonic(mnemonic); err != nil {
			logger.GetLogger().Fatal(err)
		}
	} else {
		mnemonic, err = wallet.NewMnemonic24()
		if err != nil {
			logger.GetLogger().Fatal(err)
		}
		fmt.Println("\n================ FRAZA ODZYSKIWANIA ================")
		fmt.Println(string(mnemonic))
		fmt.Println("====================================================")
		fmt.Println("Zapisz ją teraz. Nie da się jej odzyskać z klucza,")
		fmt.Println("a bez niej ani bez pliku portfela środki przepadną.")

		positions, err := randomConfirmPositions(wallet.MnemonicWordCount)
		if err != nil {
			logger.GetLogger().Fatal(err)
		}
		answers := make([]string, len(positions))
		for i, p := range positions {
			fmt.Printf("Podaj słowo numer %d: ", p)
			line, err := reader.ReadString('\n')
			if err != nil {
				logger.GetLogger().Fatal(err)
			}
			answers[i] = line
		}
		if err := checkConfirmation(string(mnemonic), positions, answers); err != nil {
			logger.GetLogger().Fatal("potwierdzenie frazy nie powiodło się: ", err)
		}
	}
	defer wallet.ZeroBytes(mnemonic)
```

Zaraz po `w.Iv = wallet.GenerateNewIv()` dodaj:

```go
	if err := w.SetMnemonic(mnemonic); err != nil {
		logger.GetLogger().Fatal(err)
	}
```

Zamień oba wywołania generowania kont:

```go
	acc, err := wallet.GenerateNewAccountFromSeed(w, w.SigName, true)
```

oraz

```go
	acc, err = wallet.GenerateNewAccountFromSeed(w, w.SigName2, false)
```

Na końcu, po `w.StoreJSON()`, wypisz adres do weryfikacji:

```go
	fmt.Printf("\nAdres portfela: %s\n", w.MainAddress.GetHex())
```

- [ ] **Step 6: Zbuduj i sprawdź ręcznie**

```bash
$GO build ./cmd/generateNewWallet/
$GO build -o /tmp/gnw cmd/generateNewWallet/main.go   # udokumentowany sposób budowania musi działać
```

Uruchom raz w trybie 1, zapisz frazę i adres. Uruchom drugi raz w trybie 2 na inny numer portfela, podaj tę samą frazę i sprawdź, że wypisany adres jest identyczny.

- [ ] **Step 7: Commit**

```bash
git add cmd/generateNewWallet/main.go cmd/generateNewWallet/prompt_test.go
git commit -m "$(cat <<'EOF'
OB-56 tryby tworzenia i odtwarzania portfela z frazy

Fraza pokazywana przed utworzeniem portfela, z wymuszonym przepisaniem trzech
losowo wybranych słów. Tryb odtwarzania buduje ten sam portfel z podanej frazy.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: GUI Qt i trwałe wyłączenie frazy przez HTTP

**Files:**
- Modify: `cmd/gui/qtwidgets/wallet.go:245-288`
- Modify: `cmd/webui/handlers/handlers.go:308`
- Modify: `cmd/website/handlers/wallet_handlers.go:138`
- Test: `cmd/webui/handlers/mnemonic_disabled_test.go`

**Interfaces:**
- Consumes: Task 5 — `GetMnemonicWords`, `RestoreSecretKeyFromMnemonic`
- Produces: brak nowych symboli

- [ ] **Step 1: Napisz test, który nie przechodzi**

Utwórz `cmd/webui/handlers/mnemonic_disabled_test.go`:

```go
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGetMnemonicIsDisabledOverHTTP: the recovery phrase gives full control of
// the wallet, so it must never travel over the network — not even to localhost,
// where it would land in browser history and caches.
func TestGetMnemonicIsDisabledOverHTTP(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			GetMnemonic(rec, httptest.NewRequest(method, "/api/wallet/mnemonic", strings.NewReader(`{"password":"x"}`)))

			if rec.Code == http.StatusOK {
				t.Fatalf("endpoint odpowiedział 200 — fraza mogła wyciec")
			}
			body := rec.Body.String()
			if !strings.Contains(strings.ToLower(body), "local") {
				t.Fatalf("odpowiedź %q nie tłumaczy, że fraza jest dostępna tylko lokalnie", body)
			}
		})
	}
}
```

- [ ] **Step 2: Uruchom test i potwierdź, że nie przechodzi**

```bash
$GO test ./cmd/webui/handlers/ -run TestGetMnemonicIsDisabled -v
```

Oczekiwane: FAIL — obecny handler wchodzi w ścieżkę z hasłem.

- [ ] **Step 3: Zastąp ciało `GetMnemonic` w `cmd/webui/handlers/handlers.go:308`**

```go
// GetMnemonic is permanently disabled. The recovery phrase derives every key of
// the wallet, so it must never cross the network: even on localhost it would end
// up in browser history, caches and any proxy in between. Use the CLI
// (cmd/generateNewWallet) or the Qt GUI, which keep it on the machine.
// The route stays registered so clients get this explanation instead of a 404.
func GetMnemonic(w http.ResponseWriter, r *http.Request) {
	jsonError(w, "The recovery phrase is available only locally, in the CLI wallet generator "+
		"or the Qt GUI. It is never served over HTTP.", http.StatusForbidden)
}
```

- [ ] **Step 4: To samo w `cmd/website/handlers/wallet_handlers.go:138`**

```go
// GetMnemonic is permanently disabled — see the note on the webui handler. This
// server is multi-user and remote, so serving recovery phrases would put every
// user's keys on the wire.
func GetMnemonic(w http.ResponseWriter, r *http.Request) {
	JsonError(w, "The recovery phrase is available only locally, in the CLI wallet generator "+
		"or the Qt GUI. It is never served over HTTP.", http.StatusForbidden)
}
```

Usuń importy, które przestały być używane w obu plikach (kompilator wskaże).

- [ ] **Step 5: Zaktualizuj etykiety w GUI (`cmd/gui/qtwidgets/wallet.go:245`)**

Zamień etykietę przycisku i tekst pola, tak by opisywały nową semantykę:

```go
	buttonMnemonic := widgets.NewQPushButton2("Show recovery phrase", nil)
	buttonMnemonic.ConnectClicked(func(bool) {
		mnemonic, err := MainWallet.GetMnemonicWords(true)
		if err != nil {
			widgets.QMessageBox_Information(nil, "OK", err.Error(), widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
			return
		}
		widgets.QMessageBox_Information(nil, "OK",
			fmt.Sprintf("Recovery phrase (24 words) — write it down and keep it offline:\n\n%v", mnemonic),
			widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
	})
	widget.Layout().AddWidget(buttonMnemonic)

	inputRestoreMnemonic := widgets.NewQLineEdit(nil)
	inputRestoreMnemonic.SetPlaceholderText("24 recovery words separated by spaces")
	widget.Layout().AddWidget(inputRestoreMnemonic)
	buttonRestoreMnemonic := widgets.NewQPushButton2("Restore keys from recovery phrase", nil)
	buttonRestoreMnemonic.ConnectClicked(func(bool) {
		phrase := inputRestoreMnemonic.Text()
		// One call rebuilds the WHOLE wallet: RestoreSecretKeyFromMnemonic ignores
		// its role argument and derives both accounts atomically (Task 5). Calling
		// it a second time would repeat both post-quantum derivations and, on a
		// transient failure, report an error for a restore that already succeeded.
		if err := MainWallet.RestoreSecretKeyFromMnemonic(phrase, true); err != nil {
			widgets.QMessageBox_Information(nil, "OK",
				fmt.Sprintf("Cannot restore the keys:\n%v", err), widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
			return
		}
		widgets.QMessageBox_Information(nil, "OK",
			fmt.Sprintf("Keys restored. Wallet address:\n%v", MainWallet.MainAddress.GetHex()),
			widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
	})
	widget.Layout().AddWidget(buttonRestoreMnemonic)
```

Zwróć uwagę: stara wersja wypisywała **klucz prywatny** w oknie dialogowym. Nowa pokazuje adres — klucz prywatny nie ma powodu pojawiać się na ekranie.

- [ ] **Step 6: Uruchom testy i zbuduj**

```bash
$GO test ./cmd/webui/handlers/ -run TestGetMnemonicIsDisabled -v
$GO build ./cmd/webui/ ./cmd/website/
```

GUI Qt buduje się tylko z zainstalowanym Qt5; jeśli `$GO build ./cmd/gui/...` zawodzi z braku Qt, odnotuj to i pomiń — zmiana jest wyłącznie w warstwie widoku.

- [ ] **Step 7: Commit**

```bash
git add cmd/gui/qtwidgets/wallet.go cmd/webui/handlers/handlers.go cmd/website/handlers/wallet_handlers.go cmd/webui/handlers/mnemonic_disabled_test.go
git commit -m "$(cat <<'EOF'
OB-56 fraza wyłącznie lokalnie, nigdy przez HTTP

Fraza wyprowadza wszystkie klucze portfela, więc nie może przechodzić przez
sieć — nawet na localhoście trafiłaby do historii i cache przeglądarki.
Przy okazji GUI przestaje wypisywać klucz prywatny w oknie dialogowym.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Known-answer test i dokumentacja

Najważniejszy test całego przedsięwzięcia. Bez niego aktualizacja liboqs, zmiana HKDF albo inna kolejność bajtów po cichu sprawi, że ta sama fraza odtworzy **inny** portfel — a użytkownik odkryje to dopiero, gdy będzie potrzebował odzysku.

**Files:**
- Create: `wallet/mnemonic_kat_test.go`
- Modify: `CLAUDE.md:134`, `README.md:160` i `:209`

**Interfaces:**
- Consumes: Task 1, 2, 3 — cała ścieżka derywacji

- [ ] **Step 1: Wygeneruj wartości odniesienia**

Ten jeden test zapisuje zaobserwowane zachowanie zamiast je przewidywać — o to właśnie chodzi: raz przypięte, nie może się już nigdy zmienić.

Utwórz tymczasowo `wallet/kat_gen_test.go`:

```go
package wallet

import (
	"fmt"
	"testing"
)

func TestGenerateKATValues(t *testing.T) {
	const phrase = "abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon art"

	w := newSeedTestWallet(t, 240)
	if err := w.SetMnemonic([]byte(phrase)); err != nil {
		t.Fatal(err)
	}
	a1, err := GenerateNewAccountFromSeed(*w, w.SigName, true)
	if err != nil {
		t.Fatal(err)
	}
	w.MainAddress = a1.Address
	a2, err := GenerateNewAccountFromSeed(*w, w.SigName2, false)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("\nKAT primary   (%s): %s\n", w.SigName, a1.Address.GetHex())
	fmt.Printf("KAT secondary (%s): %s\n\n", w.SigName2, a2.Address.GetHex())
}
```

```bash
$GO test ./wallet/ -run TestGenerateKATValues -v
```

Przepisz oba adresy z wyjścia, po czym **usuń** `wallet/kat_gen_test.go`.

- [ ] **Step 2: Napisz właściwy known-answer test**

Utwórz `wallet/mnemonic_kat_test.go`, wstawiając odczytane adresy w miejsce `<PRIMARY>` i `<SECONDARY>`:

```go
package wallet

import "testing"

// katPhrase is the standard BIP39 all-"abandon" test vector, 24-word variant.
const katPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon abandon abandon art"

// Addresses this phrase must always produce. Recorded once, from a run of the
// implementation, and never to be updated: if this test starts failing, the
// derivation changed and every wallet already created from a phrase would
// restore to a different, empty account. Investigate — do not re-record.
//
// The usual causes are a liboqs upgrade that alters how a scheme consumes its
// keygen seed, a change to hkdfSalt or detKeygenInfo, or a different active
// signature scheme in the test environment.
const (
	katPrimaryAddress   = "<PRIMARY>"
	katSecondaryAddress = "<SECONDARY>"
)

func TestKnownAnswerDerivation(t *testing.T) {
	w := newSeedTestWallet(t, 241)
	if err := w.SetMnemonic([]byte(katPhrase)); err != nil {
		t.Fatal(err)
	}

	primary, err := GenerateNewAccountFromSeed(*w, w.SigName, true)
	if err != nil {
		t.Fatal(err)
	}
	w.MainAddress = primary.Address
	secondary, err := GenerateNewAccountFromSeed(*w, w.SigName2, false)
	if err != nil {
		t.Fatal(err)
	}

	if got := primary.Address.GetHex(); got != katPrimaryAddress {
		t.Fatalf("adres podstawowy = %s, przypięty %s — derywacja się zmieniła, "+
			"istniejące frazy odtworzą inny portfel", got, katPrimaryAddress)
	}
	if got := secondary.Address.GetHex(); got != katSecondaryAddress {
		t.Fatalf("adres dodatkowy = %s, przypięty %s — derywacja się zmieniła, "+
			"istniejące frazy odtworzą inny portfel", got, katSecondaryAddress)
	}
}
```

- [ ] **Step 3: Uruchom cały pakiet dwa razy z rzędu**

```bash
$GO test ./wallet/ -count=2 -v
```

Oczekiwane: wszystkie PASS w obu przebiegach.

- [ ] **Step 4: Zaktualizuj `CLAUDE.md:134`**

Zamień fragment `the BIP39 mnemonic backup is unavailable for post-quantum keys (CW-M2 — back up the AES-256-GCM/Argon2id-encrypted wallet file instead)` na:

```
new wallets are derived from a 24-word BIP39 recovery phrase, which restores them on a clean machine (the phrase is shown once at creation and stored encrypted in the wallet file; it never travels over HTTP — CLI and Qt GUI only). Wallets created before this change have no phrase and never can, since a post-quantum secret key cannot be encoded as one (CW-M2) — back up their encrypted wallet file instead
```

- [ ] **Step 5: Zaktualizuj `README.md`**

W wierszu 160 zamień `mnemonic backup is not available for post-quantum keys` na `new wallets are created from a 24-word recovery phrase; see "Wallet backup & recovery"`.

W wierszu 209 zastąp akapit:

```
- New wallets are generated **from a 24-word BIP39 recovery phrase**. The phrase
  is shown once, before the wallet is created, and you must type three of its
  words back to continue. Keep it offline: it derives every key of the wallet,
  for the current signature schemes and any the chain votes in later.
- To restore on a clean machine, run `go run cmd/generateNewWallet/main.go` and
  pick the restore option. The same phrase always rebuilds the same addresses.
- The phrase is available only in the CLI generator and the Qt GUI. It is never
  served over HTTP, so `/api/wallet/mnemonic` returns an explanation instead.
- Wallets created before this change have no phrase — a post-quantum secret key
  is far too large to encode as one (CW-M2). Back up their AES-256-GCM /
  Argon2id-encrypted wallet file instead.
```

- [ ] **Step 6: Pełny przebieg testów**

```bash
$GO build ./... && $GO test ./wallet/ ./crypto/... ./cmd/generateNewWallet/ ./cmd/webui/... ./services/...
```

Znane, wcześniejsze porażki niezwiązane z tą zmianą: `cmd/gui/qtwidgets`, `core/abi`, `core/types`, `message`.

- [ ] **Step 7: Commit**

```bash
git add wallet/mnemonic_kat_test.go CLAUDE.md README.md
git commit -m "$(cat <<'EOF'
OB-56 known-answer test derywacji i dokumentacja

Test przypina adresy, jakie musi dać standardowa fraza testowa BIP39. Jeśli
zacznie padać, derywacja się zmieniła i każda już utworzona fraza odtworzy inny,
pusty portfel — wartości nie wolno wtedy nadpisać, tylko zbadać przyczynę.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-review planu

**Pokrycie specu.** Każda sekcja specu ma zadanie: derywacja i rozdzielenie dziedzin → Task 1; argument bezpieczeństwa wokół globalnego RNG i licznik bajtów → Task 2; format pliku, tworzenie portfela, zgodność wstecz → Task 3; zmiana schematu po głosowaniu → Task 4; odwrócona semantyka funkcji frazy → Task 5; przepływy tworzenia i odtwarzania → Task 6; wyłączenie HTTP i warstwa GUI → Task 7; known-answer test, test losowości soli (Task 2 Step 1) i dokumentacja → Task 8.

**Spójność nazw.** `SeedFromMnemonic`, `DeriveKeySeed`, `ZeroBytes`, `MnemonicWordCount` (Task 1) są używane pod tymi samymi nazwami w zadaniach 3–6. `GenerateKeyPairFromSeed` zwraca trzy wartości `(pub, drawn, err)` w Task 2 i tak samo jest wywoływana w Task 3 i 4. `EncryptedMnemonic`, `HasSeed`, `SetMnemonic`, `GenerateNewAccountFromSeed` (Task 3) występują niezmienione w zadaniach 4–6.

**Znane ograniczenie.** Task 8 Step 1 zapisuje zaobserwowaną wartość zamiast ją przewidzieć. Jest to jedyny taki krok w planie i jest zamierzony: known-answer test przypina zachowanie, którego nie da się wyliczyć niezależnie bez powtórzenia całej implementacji.


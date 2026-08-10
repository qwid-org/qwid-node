package oqs

import (
	"bytes"
	"crypto/sha512"
	"io"
	"sync"
	"testing"

	oqsrand "github.com/qwid-org/qwid-node/crypto/oqs/rand"
	"golang.org/x/crypto/hkdf"
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

// TestWipeSecretKeyLockedClearsKey is a direct regression test for finding 3's
// fix: the cleanup path GenerateKeyPairFromSeed relies on when it returns an
// error must actually destroy the secret key, not just discard the return
// value while leaving usable key material on the receiver.
func TestWipeSecretKeyLockedClearsKey(t *testing.T) {
	var sig Signature
	if err := sig.Init(testSigName, nil); err != nil {
		t.Fatal(err)
	}
	defer sig.Clean()

	if _, err := sig.GenerateKeyPair(); err != nil {
		t.Fatal(err)
	}
	if len(sig.ExportSecretKey()) == 0 {
		t.Fatal("precondition failed: no secret key to wipe")
	}

	sig.wipeSecretKeyLocked()

	if sig.ExportSecretKey() != nil {
		t.Fatal("wipeSecretKeyLocked left the receiver holding a secret key")
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
// point of randMutex: if the deterministic RNG survived keygen, subsequent
// draws from liboqs' "random" bytes would keep coming from the same HKDF
// stream instead of the system CSPRNG. That does NOT make two consecutive
// draws equal — the HKDF stream keeps advancing, so every draw yields a fresh
// value — which is why an equality check between two signatures can never
// fail here, leak or no leak. The real damage of a leak is reproducibility
// across restarts: anyone who replays the same seed through the same HKDF
// construction reproduces the exact bytes liboqs would have drawn next,
// including whatever salt/nonce those bytes seed — which is what exposes the
// private key. This test detects that by rebuilding the seed's HKDF stream
// independently, skipping past the bytes keygen consumed, and asserting that
// the next system draw does NOT match the stream's next bytes.
func TestSigningStaysRandomAfterSeededKeygen(t *testing.T) {
	var sig Signature
	if err := sig.Init(testSigName, nil); err != nil {
		t.Fatal(err)
	}
	defer sig.Clean()

	seed := seedOf(0x77)
	_, drawn, err := sig.GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}

	// Independently rebuild the exact HKDF stream keygen drew from, and skip
	// past the bytes it consumed. If the deterministic RNG leaked past keygen,
	// the next bytes liboqs draws (via oqsrand.RandomBytes below) would equal
	// streamTail, because both would be reading the same construction from the
	// same offset.
	replay := hkdf.Expand(sha512.New, seed, []byte(detKeygenInfo))
	if _, err := io.ReadFull(replay, make([]byte, drawn)); err != nil {
		t.Fatal(err)
	}
	streamTail := make([]byte, 48)
	if _, err := io.ReadFull(replay, streamTail); err != nil {
		t.Fatal(err)
	}

	got := oqsrand.RandomBytes(48)
	if bytes.Equal(got, streamTail) {
		t.Fatal("bajty pobrane po zakończeniu keygenu odpowiadają kolejnym bajtom " +
			"deterministycznego strumienia ziarna — RNG nie został przywrócony do " +
			"systemowego CSPRNG; każdy kolejny odczyt byłby odtwarzalny z frazy " +
			"odzyskiwania po restarcie procesu, co ujawnia sole, nonce i ostatecznie " +
			"klucz prywatny")
	}
}

// TestConcurrentSigningStaysRandom runs the same guarantee under -race with
// keygen and signing fighting for the global RNG. It only asserts absence of
// errors/races (via `go test -race`); it deliberately does not assert that
// concurrent signatures differ — HKDF's ever-advancing stream means a leak
// would not make two draws equal (see TestSigningStaysRandomAfterSeededKeygen
// for the assertion that actually detects a leak), so that check would never
// fail here regardless of whether randMutex is held correctly.
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
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := signer.Sign(msg); err != nil {
				t.Error(err)
			}
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

// TestConcurrentEncapSecretStaysUnderRandMutex is the regression test for
// finding 1: KeyEncapsulation.EncapSecret draws randomness through the same
// global liboqs RNG that GenerateKeyPairFromSeed temporarily replaces. Without
// randMutex around EncapSecret, running it concurrently with a seeded keygen
// can corrupt the shared HKDF reader (two goroutines advancing one SHA-512
// state at once — an unrecoverable "d.nx != 0" panic), let EncapSecret steal
// stream bytes so the same seed derives a different key pair, or exhaust the
// stream outright ("hkdf: entropy limit reached"). With the lock in place the
// two operations never overlap, so this must run clean, repeatedly, and under
// -race.
func TestConcurrentEncapSecretStaysUnderRandMutex(t *testing.T) {
	var kemAlg string
	for _, want := range []string{"ML-KEM-768", "Kyber768", "ML-KEM-512", "Kyber512"} {
		if IsKEMEnabled(want) {
			kemAlg = want
			break
		}
	}
	if kemAlg == "" {
		t.Skip("no supported KEM enabled in this liboqs build")
	}

	var kem KeyEncapsulation
	if err := kem.Init(kemAlg, nil); err != nil {
		t.Fatal(err)
	}
	defer kem.Clean()
	pub, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := kem.EncapSecret(pub); err != nil {
				t.Error(err)
			}
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
			if _, _, err := s.GenerateKeyPairFromSeed(seedOf(byte(n + 0x80))); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
}

// TestSeededKeygenReleasesTheRNGCallback: the callback installed for a
// deterministic keygen closes over an HKDF stream keyed by that key's seed.
// Switching liboqs back to the system RNG does not drop that reference — only
// clearing the callback does — so without it the seed of the last key generated
// stays reachable (and in memory dumps) for the whole process lifetime.
func TestSeededKeygenReleasesTheRNGCallback(t *testing.T) {
	var sig Signature
	if err := sig.Init(testSigName, nil); err != nil {
		t.Fatal(err)
	}
	defer sig.Clean()
	if _, _, err := sig.GenerateKeyPairFromSeed(seedOf(0x5a)); err != nil {
		t.Fatal(err)
	}
	if oqsrand.CustomAlgorithmInstalled() {
		t.Fatal("deterministic keygen left its seed-keyed RNG callback installed")
	}

	// And the process is still able to produce randomness afterwards, i.e.
	// clearing the callback did not leave liboqs pointed at nothing.
	a := oqsrand.RandomBytes(32)
	b := oqsrand.RandomBytes(32)
	if bytes.Equal(a, b) {
		t.Fatal("system RNG returned the same bytes twice after a seeded keygen")
	}
}

// TestRepeatedSeededKeygenStaysDeterministic: install/clear happens on every
// derived key (scheme changes derive more later), so the cycle must be
// repeatable — a cleared callback must not break the next derivation.
func TestRepeatedSeededKeygenStaysDeterministic(t *testing.T) {
	derive := func() []byte {
		var sig Signature
		if err := sig.Init(testSigName, nil); err != nil {
			t.Fatal(err)
		}
		defer sig.Clean()
		pub, _, err := sig.GenerateKeyPairFromSeed(seedOf(0x11))
		if err != nil {
			t.Fatal(err)
		}
		return pub
	}
	first := derive()
	for i := 0; i < 3; i++ {
		if !bytes.Equal(first, derive()) {
			t.Fatalf("derivation %d differs from the first: install/clear cycle is not repeatable", i+2)
		}
		if oqsrand.CustomAlgorithmInstalled() {
			t.Fatalf("callback still installed after derivation %d", i+2)
		}
	}
}

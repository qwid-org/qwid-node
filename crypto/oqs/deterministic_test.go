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

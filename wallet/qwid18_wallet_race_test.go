package wallet

import (
	"sync"
	"testing"
)

// QWID-2026-18: the Wallet now carries a per-instance RWMutex taken by Sign
// (RLock) and by Wipe / AddNewEncryptionToActiveWallet / StoreJSON (Lock), so a
// signer is never freed or half-swapped under a concurrent Sign.
//
// NOTE ON -race: this package cannot be run under `-race`. The oqs custom-RNG
// binding (crypto/oqs/rand/rand.go) trips `checkptr: pointer arithmetic result
// points to invalid allocation` during every key generation under the race
// build — a pre-existing oqs limitation, unrelated to this fix, that fires on
// stock tests such as TestRestoreFromMnemonicRebuildsTheSameKeys too. These
// tests therefore assert no deadlock and no panic under concurrency; the
// data-race freedom itself rests on every shared-signer access now routing
// through the lock (see Sign/Wipe/AddNewEncryptionToActiveWallet/StoreJSON).

// TestQWID18_ConcurrentSignAndSchemeRewrite drives many concurrent Sign calls
// against a concurrent scheme-key rewrite. Without the lock the rewrite could
// free/replace Account1.signer mid-Sign; with it the two serialize and neither
// deadlocks nor panics.
func TestQWID18_ConcurrentSignAndSchemeRewrite(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 231)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)

	var signers sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		signers.Add(1)
		go func() {
			defer signers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = w.Sign([]byte("qwid-race"), true) // errors tolerated
			}
		}()
	}

	var rewriter sync.WaitGroup
	rewriter.Add(1)
	go func() {
		defer rewriter.Done()
		for i := 0; i < 50; i++ {
			_ = w.AddNewEncryptionToActiveWallet(w.SigName, true)
		}
	}()

	rewriter.Wait()
	close(stop)
	signers.Wait()

	// The wallet must still sign after the concurrent churn.
	if _, err := w.Sign([]byte("qwid-final"), true); err != nil {
		t.Fatalf("wallet cannot sign after concurrent rewrite: %v", err)
	}
}

// TestQWID18_ConcurrentSignAndWipe confirms Sign concurrent with Wipe neither
// deadlocks nor panics: Wipe waits for in-flight signers before freeing the
// signer context, and a Sign scheduled after Wipe returns an error rather than
// touching freed material.
func TestQWID18_ConcurrentSignAndWipe(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 232)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = w.Sign([]byte("qwid-wipe"), true)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.Wipe()
	}()
	wg.Wait()
}

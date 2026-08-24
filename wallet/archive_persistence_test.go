package wallet

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// OB-55: the per-scheme key archive (w.Accounts) was silently destroyed on every
// save of a wallet that had been loaded from disk.
//
// Account.secretKey is unexported, so it is never serialised: for every archive
// entry read back from the wallet file it is the zero value. StoreJSON,
// ChangePassword and ChangePasswordInPlace all encrypted that zero value and then
// spliced the resulting ~28-byte GCM blob over the HEAD of the real ciphertext
// with copy(), leaving the tail intact and the entry undecryptable forever.
//
// The damage was invisible to the tests that existed because they only ever
// exercised entries created in the SAME session, where secretKey is live and the
// two ciphertexts are the same length — so copy() happened to be a full
// overwrite. Every test below therefore goes through at least one store/reload
// cycle before asserting; that is the whole point.

// legacyArchiveWallet builds a phrase-less wallet with both accounts populated,
// in a throwaway directory. Phrase-less on purpose: it is the case where the
// archive is the only key store there is, so archive corruption is unrecoverable.
func legacyArchiveWallet(t *testing.T, number uint8) *Wallet {
	t.Helper()
	w := newSeedTestWallet(t, number)
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
	if w.HasSeed() {
		t.Fatal("test setup: wallet unexpectedly has a seed")
	}
	return w
}

// assertArchiveMatches checks that every scheme named in want is present in w's
// per-scheme archive, decrypts under w's current password, and yields the key it
// was stored with. Schemes not named in want are ignored, so a test can plant a
// deliberately broken entry alongside healthy ones.
func assertArchiveMatches(t *testing.T, w *Wallet, want map[string][]byte) {
	t.Helper()
	for scheme, expected := range want {
		entry, ok := w.Accounts[scheme]
		if !ok {
			t.Fatalf("archive lost its entry for scheme %q", scheme)
		}
		actual, err := w.decrypt(entry.EncryptedSecretKey)
		if err != nil {
			t.Fatalf("archived key for scheme %q does not decrypt (%d ciphertext bytes): %v",
				scheme, len(entry.EncryptedSecretKey), err)
		}
		// The stored blob is the full exported secret key; the load path
		// truncates its own copy to the scheme's secret-key length, so compare on
		// the prefix the shorter of the two defines.
		n := len(expected)
		if len(actual) < n {
			n = len(actual)
		}
		if n == 0 {
			t.Fatalf("archived key for scheme %q decrypted to nothing", scheme)
		}
		if !bytes.Equal(actual[:n], expected[:n]) {
			t.Fatalf("archived key for scheme %q changed: got %d bytes, which do not match the %d bytes it was stored with",
				scheme, len(actual), len(expected))
		}
	}
}

// TestStoreJSONKeepsArchiveDecryptableAfterReload is the core regression test:
// load a wallet that has archive entries from disk, save it, reload it, and every
// archive entry must still decrypt to the key it held before.
//
// It needs no scheme change at all — StoreJSON archives the primary and secondary
// accounts by itself, so this is precisely what happened to the operator's
// wallets on every single node restart.
func TestStoreJSONKeepsArchiveDecryptableAfterReload(t *testing.T) {
	w := legacyArchiveWallet(t, 240)
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}
	if len(w.Accounts) < 2 {
		t.Fatalf("test setup: expected StoreJSON to archive both accounts, got %d entries", len(w.Accounts))
	}
	want := map[string][]byte{
		w.SigName:  append([]byte(nil), w.Account1.secretKey.GetBytes()...),
		w.SigName2: append([]byte(nil), w.Account2.secretKey.GetBytes()...),
	}

	// First reload. loadWalletFromStruct ends with its own StoreJSON, so the
	// archive has already been written once from a disk-loaded (empty-secretKey)
	// state by the time this returns.
	loaded, err := LoadJSONFromDir(w.HomePath, 240, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not reload: %v", err)
	}
	assertArchiveMatches(t, loaded, want)

	// An explicit save of the reloaded wallet, then another reload — the exact
	// cycle a node restart performs.
	if err := loaded.StoreJSON(); err != nil {
		t.Fatal(err)
	}
	again, err := LoadJSONFromDir(w.HomePath, 240, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not reload after being saved from its reloaded form: %v", err)
	}
	assertArchiveMatches(t, again, want)

	// A third cycle, to prove the damage was not merely deferred.
	if err := again.StoreJSON(); err != nil {
		t.Fatal(err)
	}
	third, err := LoadJSONFromDir(w.HomePath, 240, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not reload on the third cycle: %v", err)
	}
	assertArchiveMatches(t, third, want)
}

// TestChangePasswordOnReloadedWalletOpensArchiveWithNewPassword covers
// ChangePassword on a wallet loaded from disk. Before the fix this returned an
// error (reported to the operator as a bare "wrong password") because the archive
// entries it tried to decrypt had already been destroyed by StoreJSON.
//
// ChangePassword reloads through LoadJSON, which always resolves the wallet's
// home-directory path via os.UserHomeDir(), so this test redirects $HOME instead
// of setting HomePath — see the note on TestChangePasswordPreservesMnemonic.
func TestChangePasswordOnReloadedWalletOpensArchiveWithNewPassword(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	w := EmptyWallet(241, common.SigName(), common.SigName2())
	w.SetPassword("test-password-123")
	w.Iv = GenerateNewIv()
	acc, err := GenerateNewAccount(w, w.SigName)
	if err != nil {
		t.Fatal(err)
	}
	w.MainAddress = acc.Address
	w.Account1 = acc
	acc2, err := GenerateNewAccount(w, w.SigName2)
	if err != nil {
		t.Fatal(err)
	}
	w.Account2 = acc2
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{
		w.SigName:  append([]byte(nil), w.Account1.secretKey.GetBytes()...),
		w.SigName2: append([]byte(nil), w.Account2.secretKey.GetBytes()...),
	}

	// Reload first: that is what makes the archive entries secretKey-less, which
	// is the whole condition under which this used to break.
	loaded, err := LoadJSON(241, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not reload: %v", err)
	}

	if err := loaded.ChangePassword("test-password-123", "new-password-456"); err != nil {
		t.Fatalf("ChangePassword failed on a reloaded wallet: %v", err)
	}

	// The in-memory wallet has picked up the reloaded archive under the new key.
	assertArchiveMatches(t, loaded, want)

	// And the file opens with the new password, archive included.
	reopened, err := LoadJSON(241, "new-password-456", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not open with the new password: %v", err)
	}
	assertArchiveMatches(t, reopened, want)

	if _, err := LoadJSON(241, "test-password-123", w.SigName, w.SigName2); err == nil {
		t.Fatal("wallet still opens with the OLD password after ChangePassword")
	}
}

// TestChangePasswordInPlaceOnReloadedWalletOpensArchiveWithNewPassword is the
// ChangePasswordInPlace counterpart (the path used by the website's multi-user
// wallets, which live outside the home directory).
func TestChangePasswordInPlaceOnReloadedWalletOpensArchiveWithNewPassword(t *testing.T) {
	w := legacyArchiveWallet(t, 242)
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{
		w.SigName:  append([]byte(nil), w.Account1.secretKey.GetBytes()...),
		w.SigName2: append([]byte(nil), w.Account2.secretKey.GetBytes()...),
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 242, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not reload: %v", err)
	}

	if err := loaded.ChangePasswordInPlace("test-password-123", "new-password-456"); err != nil {
		t.Fatalf("ChangePasswordInPlace failed on a reloaded wallet: %v", err)
	}
	assertArchiveMatches(t, loaded, want)

	reopened, err := LoadJSONFromDir(w.HomePath, 242, "new-password-456", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not open with the new password: %v", err)
	}
	assertArchiveMatches(t, reopened, want)

	if _, err := LoadJSONFromDir(w.HomePath, 242, "test-password-123", w.SigName, w.SigName2); err == nil {
		t.Fatal("wallet still opens with the OLD password after ChangePasswordInPlace")
	}
}

// TestChangePasswordInPlaceKeepsUndecryptableArchiveEntry pins the policy chosen
// for OB-55: an archived key that cannot be decrypted under the (already
// verified) current password does NOT abort the password change, and is NOT
// dropped — it is carried over untouched and logged. Aborting is what left
// wallets damaged by this very bug unable to change their password at all;
// dropping would be the one irreversible act in a routine operation, and the
// blob may simply be under an older password.
func TestChangePasswordInPlaceKeepsUndecryptableArchiveEntry(t *testing.T) {
	w := legacyArchiveWallet(t, 243)
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 243, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatal(err)
	}

	// A blob that authenticates against nothing, standing in for an entry already
	// wrecked by the pre-fix code, or one left under an older password.
	junk := []byte("this is not a valid AES-GCM ciphertext at all, on purpose")
	entry := loaded.Accounts[loaded.SigName2]
	entry.EncryptedSecretKey = append([]byte(nil), junk...)
	loaded.Accounts[loaded.SigName2] = entry

	if err := loaded.ChangePasswordInPlace("test-password-123", "new-password-456"); err != nil {
		t.Fatalf("password change must not abort on one undecryptable archive entry: %v", err)
	}

	reopened, err := LoadJSONFromDir(w.HomePath, 243, "new-password-456", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not open with the new password: %v", err)
	}
	kept, ok := reopened.Accounts[w.SigName2]
	if !ok {
		t.Fatal("the undecryptable archive entry was dropped; it must be kept untouched")
	}
	if !bytes.Equal(kept.EncryptedSecretKey, junk) {
		t.Fatalf("the undecryptable archive entry was rewritten (%d bytes); it must be carried over byte for byte",
			len(kept.EncryptedSecretKey))
	}
	// The healthy entry still made the trip.
	assertArchiveMatches(t, reopened, map[string][]byte{
		w.SigName: append([]byte(nil), w.Account1.secretKey.GetBytes()...),
	})
}

// TestReloadedLegacyWalletSchemeChangeRecoversArchivedKey: a phrase-less wallet
// that holds an archived key for the scheme the chain just voted in must still be
// able to use it AFTER a store/reload cycle. TestLegacyWalletSchemeChangeStillUsesArchive
// only ever exercised a same-session archive entry, which is why it passed even
// with the archive-corrupting code in place.
func TestReloadedLegacyWalletSchemeChangeRecoversArchivedKey(t *testing.T) {
	w := legacyArchiveWallet(t, 244)
	originalSigName := w.SigName

	withSchemeChangeTarget(t)

	archived, err := GenerateNewAccount(*w, schemeChangeTarget)
	if err != nil {
		t.Fatal(err)
	}
	w.Accounts[schemeChangeTarget] = archived
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}
	wantArchivedKey := append([]byte(nil), archived.secretKey.GetBytes()...)

	// Reload once under the ORIGINAL schemes. This is the store/reload cycle that
	// used to wreck the archived Falcon-1024 entry: it is present in the file,
	// has no live secretKey, and loadWalletFromStruct saves the wallet again on
	// its way out.
	reloaded, err := LoadJSONFromDir(w.HomePath, 244, "test-password-123", originalSigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not reload under its original schemes: %v", err)
	}
	assertArchiveMatches(t, reloaded, map[string][]byte{schemeChangeTarget: wantArchivedKey})

	// Now the chain switches. The archived key must be recovered and usable.
	switched, err := LoadJSONFromDir(w.HomePath, 244, "test-password-123", schemeChangeTarget, w.SigName2)
	if err != nil {
		t.Fatalf("phrase-less wallet failed a scheme change it holds an archived key for: %v", err)
	}
	if switched.Account1.Address.GetHex() != archived.Address.GetHex() {
		t.Fatalf("Account1 = %s, expected the archived key %s",
			switched.Account1.Address.GetHex(), archived.Address.GetHex())
	}
	if _, err := switched.Sign([]byte("qwid"), true); err != nil {
		t.Fatalf("recovered archived key does not sign: %v", err)
	}
}

// TestReloadedSeededWalletSchemeChangeIgnoresReadableArchive is the guard on the
// entanglement between this fix and 87b5024 (finding I1).
//
// Before this fix, a stale/foreign archive entry was unreadable by the time it
// mattered, so a seeded wallet meeting it failed LOUDLY. Making the archive
// readable again would, on its own, turn that loud failure into a silent identity
// swap. This test arms the trap explicitly — it asserts the foreign entry IS
// decryptable at the moment of the scheme change (which is only true after this
// fix) — and then requires the phrase to win anyway.
func TestReloadedSeededWalletSchemeChangeIgnoresReadableArchive(t *testing.T) {
	phraseA, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	phraseB, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	w := newSeedTestWallet(t, 245)
	if err := w.SetMnemonic(phraseA); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)
	originalSigName := w.SigName

	withSchemeChangeTarget(t)

	// What phrase A derives for the new scheme — the only correct answer.
	expected, err := GenerateNewAccountFromSeed(*w, schemeChangeTarget, true)
	if err != nil {
		t.Fatal(err)
	}

	// A foreign entry for the new scheme: another phrase's key, but encrypted
	// under THIS wallet's password, so it would load perfectly cleanly if the
	// load path ever preferred it.
	foreignSeed, err := SeedFromMnemonic(phraseB)
	if err != nil {
		t.Fatal(err)
	}
	scratch := *w
	scratch.seed = foreignSeed
	foreign, err := GenerateNewAccountFromSeed(scratch, schemeChangeTarget, true)
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Address.GetHex() == expected.Address.GetHex() {
		t.Fatal("test setup: foreign key equals the derived one")
	}
	w.Accounts[schemeChangeTarget] = foreign
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	// Store/reload cycle under the original schemes, so the foreign entry goes
	// through StoreJSON with no live secretKey — the exact path that used to
	// destroy it.
	reloaded, err := LoadJSONFromDir(w.HomePath, 245, "test-password-123", originalSigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not reload under its original schemes: %v", err)
	}
	// Arm the trap: the archive entry must be genuinely usable here, otherwise
	// the assertion below would pass for the wrong reason (a loud decrypt
	// failure rather than the seed actually outranking the archive).
	assertArchiveMatches(t, reloaded, map[string][]byte{
		schemeChangeTarget: append([]byte(nil), foreign.secretKey.GetBytes()...),
	})

	// See the matching note in TestSchemeChangeSeedOutranksStaleArchive: a
	// scheme change swaps the key, not the wallet's identity.
	originalMain := w.MainAddress.GetHex()

	switched, err := LoadJSONFromDir(w.HomePath, 245, "test-password-123", schemeChangeTarget, w.SigName2)
	if err != nil {
		t.Fatalf("seeded wallet failed a scheme change it should have derived: %v", err)
	}
	if switched.Account1.Address.GetHex() != expected.Address.GetHex() {
		t.Fatalf("Account1 = %s, expected the phrase-derived key %s (the readable archive entry %s won instead)",
			switched.Account1.Address.GetHex(), expected.Address.GetHex(), foreign.Address.GetHex())
	}
	if switched.MainAddress.GetHex() != originalMain {
		t.Fatalf("MainAddress moved to %s after a scheme change; it must stay %s",
			switched.MainAddress.GetHex(), originalMain)
	}
	// And the archive was refreshed with what the phrase derives, so the foreign
	// entry cannot come back on a later load.
	if got, ok := switched.Accounts[schemeChangeTarget]; ok {
		if got.Address.GetHex() == foreign.Address.GetHex() {
			t.Fatalf("the foreign archive entry for %q survived the load (%s)",
				schemeChangeTarget, got.Address.GetHex())
		}
		if got.Address.GetHex() != expected.Address.GetHex() {
			t.Fatalf("archive entry for %q = %s, expected the phrase-derived %s",
				schemeChangeTarget, got.Address.GetHex(), expected.Address.GetHex())
		}
	}
}

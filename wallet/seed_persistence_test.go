package wallet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// newSeedTestWallet builds a wallet whose files land in a throwaway directory.
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
		t.Fatal("expected an error for an invalid phrase")
	}
	if w.HasSeed() {
		t.Fatal("the wallet has a seed even though the phrase was rejected")
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
		t.Fatalf("the same phrase produced different addresses: %s vs %s",
			w1.MainAddress.GetHex(), w2.MainAddress.GetHex())
	}
	if w1.Account2.Address.GetHex() != w2.Account2.Address.GetHex() {
		t.Fatal("the same phrase produced different second-account addresses")
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
		t.Fatal("different phrases produced the same address")
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
		t.Fatal("StoreJSON did not write the encrypted phrase")
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 203, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.HasSeed() {
		t.Fatal("the loaded wallet has no seed")
	}
	if loaded.MainAddress.GetHex() != w.MainAddress.GetHex() {
		t.Fatal("the address changed across a save and load")
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
		t.Fatal("a wallet with no phrase wrote an empty encrypted_mnemonic field — omitempty is missing")
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 204, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("an old-style wallet failed to load: %v", err)
	}
	if loaded.HasSeed() {
		t.Fatal("an old-style wallet reports that it has a seed")
	}
	if _, err := loaded.Sign([]byte("qwid"), true); err != nil {
		t.Fatalf("an old-style wallet cannot sign: %v", err)
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

	// Capture the slice header before Wipe(): w.seed = nil alone would satisfy
	// !w.HasSeed() without proving the backing array was actually zeroed, so
	// keep our own handle on the same backing array and check every byte of it,
	// the way TestWipeCleansesSecretKeys does for the secret keys.
	seedBackup := w.seed
	if len(seedBackup) == 0 {
		t.Fatal("test setup: seed is empty before Wipe")
	}

	w.Wipe()

	if w.HasSeed() {
		t.Fatal("Wipe did not clear the seed")
	}
	for i, b := range seedBackup {
		if b != 0 {
			t.Fatalf("seed byte %d = %d, want 0 (Wipe must zero the backing array, not just nil the slice)", i, b)
		}
	}
}

func readWalletFile(t *testing.T, dir string, number uint8) (string, error) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "wallet"+strconv.Itoa(int(number))+".json"))
	return string(b), err
}

// --- Finding 1: password change must not destroy the recovery phrase ---

// TestChangePasswordPreservesMnemonic covers ChangePassword. Unlike
// ChangePasswordInPlace, ChangePassword reloads via LoadJSON, which always
// resolves the wallet's default (home-directory) path via os.UserHomeDir()
// rather than a caller-chosen one, so this test cannot point HomePath at a
// t.TempDir() directly the way the others in this file do. Instead it
// redirects os.UserHomeDir() itself with t.Setenv("HOME", t.TempDir()): on
// Linux os.UserHomeDir() reads $HOME, so this isolates both StoreJSON and
// ChangePassword's internal LoadJSON without ever touching the operator's
// real ~/.qwid. t.Setenv is legal here because nothing in this package calls
// t.Parallel().
func TestChangePasswordPreservesMnemonic(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", t.TempDir())

	w := EmptyWallet(210, common.SigName(), common.SigName2())
	w.SetPassword("test-password-123")
	w.Iv = GenerateNewIv()
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, &w)
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	if err := w.ChangePassword("test-password-123", "new-password-456"); err != nil {
		t.Fatal(err)
	}

	if !w.HasSeed() {
		t.Fatal("HasSeed() is false right after ChangePassword: recovery phrase was lost")
	}
	got, err := w.decrypt(w.EncryptedMnemonic)
	if err != nil {
		t.Fatalf("cannot decrypt the recovery phrase after ChangePassword: %v", err)
	}
	if string(got) != string(mnemonic) {
		t.Fatal("recovery phrase changed after ChangePassword")
	}

	loaded, err := LoadJSON(210, "new-password-456", w.SigName, w.SigName2)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.HasSeed() {
		t.Fatal("reloaded wallet has no seed after ChangePassword")
	}
	gotReloaded, err := loaded.decrypt(loaded.EncryptedMnemonic)
	if err != nil {
		t.Fatalf("cannot decrypt the reloaded recovery phrase: %v", err)
	}
	if string(gotReloaded) != string(mnemonic) {
		t.Fatal("recovery phrase changed after ChangePassword + reload from disk")
	}
}

// TestChangePasswordInPlacePreservesMnemonic covers ChangePasswordInPlace,
// which used to swap w.passwordBytes to the new key before StoreJSON tried to
// re-encrypt EncryptedMnemonic — decrypting an old-key blob with the new key,
// failing, and silently persisting a phrase that could never be opened again.
func TestChangePasswordInPlacePreservesMnemonic(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 211)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	if err := w.ChangePasswordInPlace("test-password-123", "new-password-456"); err != nil {
		t.Fatal(err)
	}

	if !w.HasSeed() {
		t.Fatal("HasSeed() is false after ChangePasswordInPlace: recovery phrase was lost")
	}
	got, err := w.decrypt(w.EncryptedMnemonic)
	if err != nil {
		t.Fatalf("cannot decrypt the recovery phrase after ChangePasswordInPlace: %v", err)
	}
	if string(got) != string(mnemonic) {
		t.Fatal("recovery phrase changed after ChangePasswordInPlace")
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 211, "new-password-456", w.SigName, w.SigName2)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.HasSeed() {
		t.Fatal("reloaded wallet has no seed after ChangePasswordInPlace")
	}
	gotReloaded, err := loaded.decrypt(loaded.EncryptedMnemonic)
	if err != nil {
		t.Fatalf("cannot decrypt the reloaded recovery phrase: %v", err)
	}
	if string(gotReloaded) != string(mnemonic) {
		t.Fatal("recovery phrase changed after ChangePasswordInPlace + reload from disk")
	}
}

// --- Item 3 (round 2 review): a password change must degrade, not abort,
// when the stored phrase is already undecryptable under the (verified
// correct) current password. Matches the degrade-not-abort rule from loading
// (Finding 4): the blob is dropped rather than carried forward, since it
// provably can never decrypt under any password from this point on. ---

func TestChangePasswordInPlaceDropsUndecryptableMnemonic(t *testing.T) {
	w := newSeedTestWallet(t, 217)
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
	// Not produced by SetMnemonic/encrypt on purpose: this must fail AES-GCM
	// authentication, simulating a phrase blob that is already unrecoverable
	// (e.g. via the corruption scenario TestCorruptedMnemonicDegradesGracefully
	// covers on the load side).
	w.EncryptedMnemonic = []byte("this is not a valid AES-GCM ciphertext at all, on purpose")
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	if err := w.ChangePasswordInPlace("test-password-123", "new-password-456"); err != nil {
		t.Fatalf("ChangePasswordInPlace must degrade, not abort, on an undecryptable stored phrase: %v", err)
	}
	if len(w.EncryptedMnemonic) != 0 {
		t.Fatal("expected the undecryptable recovery phrase blob to be dropped, not carried forward")
	}
	if w.HasSeed() {
		t.Fatal("wallet must not report HasSeed() true for a phrase it could never decrypt")
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 217, "new-password-456", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not accept the new password: %v", err)
	}
	if loaded.HasSeed() {
		t.Fatal("reloaded wallet reports HasSeed() true despite a dropped, undecryptable phrase")
	}
	if len(loaded.EncryptedMnemonic) != 0 {
		t.Fatal("expected the undecryptable recovery phrase blob to stay dropped in the stored file")
	}
}

// TestChangePasswordDropsUndecryptableMnemonic is the ChangePassword
// (not-in-place) counterpart; see the isolation note on
// TestChangePasswordPreservesMnemonic for why it uses t.Setenv("HOME", ...)
// instead of newSeedTestWallet.
func TestChangePasswordDropsUndecryptableMnemonic(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	w := EmptyWallet(218, common.SigName(), common.SigName2())
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
	w.EncryptedMnemonic = []byte("this is not a valid AES-GCM ciphertext at all, on purpose")
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	if err := w.ChangePassword("test-password-123", "new-password-456"); err != nil {
		t.Fatalf("ChangePassword must degrade, not abort, on an undecryptable stored phrase: %v", err)
	}

	loaded, err := LoadJSON(218, "new-password-456", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not accept the new password: %v", err)
	}
	if loaded.HasSeed() {
		t.Fatal("reloaded wallet reports HasSeed() true despite a dropped, undecryptable phrase")
	}
	if len(loaded.EncryptedMnemonic) != 0 {
		t.Fatal("expected the undecryptable recovery phrase blob to be dropped from the stored file")
	}
}

// --- Finding 2: a seedless wallet must never silently mint a random identity
// on a chain-forced scheme change ---

// schemeChangeTarget is a signature scheme distinct from the wallet defaults
// (Falcon-512 / MAYO-5) used to exercise loadWalletFromStruct's scheme-change
// branches without colliding with an already-populated Accounts map entry.
const (
	schemeChangeTarget           = "Falcon-1024"
	schemeChangeTargetPubKeyLen  = 1793
	schemeChangeTargetPrivKeyLen = 2305
	schemeChangeTargetSigLen     = 1462
)

// withSchemeChangeTarget points the package-global primary-scheme config
// (common.SigName/PubKeyLength/...) at schemeChangeTarget for the duration of
// the test, restoring whatever was configured before on cleanup.
// common.PubKey.Init validates a derived public key's length against this
// global config (not against whatever scheme name was asked for), mirroring
// how a real scheme-change vote updates it in production via
// common.SetEncryption before the node reloads its wallet with the new names.
func withSchemeChangeTarget(t *testing.T) {
	t.Helper()
	origSigName := common.SigName()
	origPub := common.PubKeyLength(false)
	origPriv := common.PrivateKeyLength()
	origSig := common.SignatureLength(false)
	common.SetEncryption(schemeChangeTarget, schemeChangeTargetPubKeyLen, schemeChangeTargetPrivKeyLen, schemeChangeTargetSigLen, false, true)
	t.Cleanup(func() {
		common.SetEncryption(origSigName, origPub, origPriv, origSig, false, true)
	})
}

// TestSeededWalletSchemeChangeDerivesDeterministically verifies that when the
// wallet has a seed, a scheme change derives the same address from the same
// phrase every time, independent of which wallet instance derives it.
func TestSeededWalletSchemeChangeDerivesDeterministically(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	w1 := newSeedTestWallet(t, 212)
	if err := w1.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w1)
	if err := w1.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	w2 := newSeedTestWallet(t, 213)
	if err := w2.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w2)
	if err := w2.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	withSchemeChangeTarget(t)

	loaded1, err := LoadJSONFromDir(w1.HomePath, 212, "test-password-123", schemeChangeTarget, w1.SigName2)
	if err != nil {
		t.Fatalf("seeded wallet failed a scheme change it should have derived: %v", err)
	}
	loaded2, err := LoadJSONFromDir(w2.HomePath, 213, "test-password-123", schemeChangeTarget, w2.SigName2)
	if err != nil {
		t.Fatalf("seeded wallet failed a scheme change it should have derived: %v", err)
	}

	if loaded1.SigName != schemeChangeTarget || loaded2.SigName != schemeChangeTarget {
		t.Fatalf("SigName not updated to the new scheme: %q / %q", loaded1.SigName, loaded2.SigName)
	}
	if !loaded1.HasSeed() || !loaded2.HasSeed() {
		t.Fatal("expected the seed to survive a scheme change")
	}
	if loaded1.Account1.Address.GetHex() != loaded2.Account1.Address.GetHex() {
		t.Fatalf("scheme change derived different addresses from the same phrase: %s vs %s",
			loaded1.Account1.Address.GetHex(), loaded2.Account1.Address.GetHex())
	}
	if loaded1.MainAddress.GetHex() != loaded2.MainAddress.GetHex() {
		t.Fatalf("scheme change derived different MainAddress from the same phrase: %s vs %s",
			loaded1.MainAddress.GetHex(), loaded2.MainAddress.GetHex())
	}
}

// TestLegacyWalletSchemeChangeFailsSafely verifies that a seedless wallet
// meeting an unknown scheme change refuses to generate a random key (which
// would silently and irrecoverably replace its staked identity) and, since
// loadWalletFromStruct returns before persisting anything, leaves the
// on-disk MainAddress untouched.
func TestLegacyWalletSchemeChangeFailsSafely(t *testing.T) {
	w := newSeedTestWallet(t, 214)
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
	originalMainAddress := w.MainAddress.GetHex()

	// Reconfigure the global scheme, the way a real scheme-change vote would
	// before the node reloads its wallet. Without this, the length check in
	// common.PubKey.Init would have rejected the pre-fix (always-generate)
	// behavior anyway, for an unrelated reason, and this test would pass for
	// the wrong reason regardless of whether the production fix under test is
	// present.
	withSchemeChangeTarget(t)

	_, err = LoadJSONFromDir(w.HomePath, 214, "test-password-123", schemeChangeTarget, w.SigName2)
	if err == nil {
		t.Fatal("expected an error when a seedless wallet meets an unknown scheme change")
	}
	if !strings.Contains(err.Error(), schemeChangeTarget) {
		t.Fatalf("error does not name the new scheme %q: %v", schemeChangeTarget, err)
	}

	reloaded, err := LoadJSONFromDir(w.HomePath, 214, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet did not reload cleanly with its original scheme after the failed change: %v", err)
	}
	if reloaded.MainAddress.GetHex() != originalMainAddress {
		t.Fatalf("MainAddress mutated by a failed scheme change: got %s want %s",
			reloaded.MainAddress.GetHex(), originalMainAddress)
	}
}

// --- Finding 4: a corrupted stored phrase must degrade, never abort ---

// TestCorruptedMnemonicDegradesGracefully verifies that a wallet file whose
// encrypted_mnemonic field has been corrupted (or was written under a key the
// current password no longer matches) still loads and still signs; it simply
// reports HasSeed() == false instead of failing to load altogether.
func TestCorruptedMnemonicDegradesGracefully(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 215)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	walletFile := filepath.Join(w.HomePath, "wallet215.json")
	data, err := os.ReadFile(walletFile)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk Wallet
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatal(err)
	}
	if len(onDisk.EncryptedMnemonic) == 0 {
		t.Fatal("test setup: wallet file has no encrypted_mnemonic to corrupt")
	}
	onDisk.EncryptedMnemonic = []byte("this is not a valid AES-GCM ciphertext at all")
	corrupted, err := json.MarshalIndent(&onDisk, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(walletFile, corrupted, 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 215, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("wallet with a corrupted recovery phrase failed to load: %v", err)
	}
	if loaded.HasSeed() {
		t.Fatal("wallet reports HasSeed() true despite an undecryptable stored phrase")
	}
	if _, err := loaded.Sign([]byte("qwid"), true); err != nil {
		t.Fatalf("wallet with a corrupted recovery phrase failed to sign: %v", err)
	}
}

// --- Minor: GenerateNewAccountFromSeed must not derive from a wrong-length or
// all-zero seed (e.g. a struct copy taken just before the original's Wipe()) ---

func TestGenerateNewAccountFromSeedRejectsZeroedSeed(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 216)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}

	// Simulate a struct copy taken just before the original's Wipe() runs: the
	// copy shares the same seed backing array, so zeroing the original also
	// zeroes what the copy sees, while the copy's slice length (and therefore
	// HasSeed()) is unaffected.
	wCopy := *w
	if !wCopy.HasSeed() {
		t.Fatal("test setup: copy should still report HasSeed() true")
	}
	w.Wipe()
	if !wCopy.HasSeed() {
		t.Fatal("test setup: copy's HasSeed() must remain true even though the backing array is now zero")
	}

	if _, err := GenerateNewAccountFromSeed(wCopy, wCopy.SigName, true); err == nil {
		t.Fatal("expected an error deriving a key from a zeroed-out seed")
	}
}

// --- I1: the recovery phrase outranks the per-scheme key archive ---

// readStoredAccountAddresses reads the wallet file straight off disk and returns
// account_1.address and, per scheme, accounts[<scheme>].address. Deliberately
// bypasses LoadJSON: the point is what was PERSISTED, independent of what the
// load path would then make of it.
func readStoredAccountAddresses(t *testing.T, dir string, number uint8) (account1 string, archive map[string]string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "wallet"+strconv.Itoa(int(number))+".json"))
	if err != nil {
		t.Fatal(err)
	}
	// common.Address marshals through MarshalText, i.e. as a hex string.
	type storedAccount struct {
		Address string `json:"address"`
	}
	var stored struct {
		Account1 storedAccount            `json:"account_1"`
		Accounts map[string]storedAccount `json:"accounts"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	norm := func(s string) string { return strings.ToLower(strings.TrimPrefix(s, "0x")) }
	archive = map[string]string{}
	for k, v := range stored.Accounts {
		archive[k] = norm(v.Address)
	}
	return norm(stored.Account1.Address), archive
}

// TestRestoreFromDifferentPhraseLeavesNoStaleArchive is the reviewer's probe:
// create a seeded wallet, restore it from a DIFFERENT phrase, store it, and the
// file must not end up holding two disagreeing identities — account_1 from the
// new phrase and accounts["<scheme>"] from the old one. Before the fix both were
// persisted, and the load path preferred the archive, so the wallet came back as
// its PRE-restore identity.
//
// The assertions read the stored file directly and then reload it, so this test
// is independent of the separate, out-of-scope StoreJSON archive-re-encryption
// bug: it compares addresses (which that bug does not touch), not ciphertext.
func TestRestoreFromDifferentPhraseLeavesNoStaleArchive(t *testing.T) {
	phraseA, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	phraseB, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	w := newSeedTestWallet(t, 230)
	if err := w.SetMnemonic(phraseA); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}
	addressFromA := w.MainAddress.GetHex()

	if err := w.RestoreSecretKeyFromMnemonic(string(phraseB), true); err != nil {
		t.Fatal(err)
	}
	addressFromB := w.MainAddress.GetHex()
	if addressFromB == addressFromA {
		t.Fatal("test setup: two different phrases produced the same wallet")
	}
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	storedAccount1, storedArchive := readStoredAccountAddresses(t, w.HomePath, 230)
	if storedAccount1 != addressFromB {
		t.Fatalf("account_1.address = %s, expected the identity from the new phrase %s", storedAccount1, addressFromB)
	}
	if got, ok := storedArchive[w.SigName]; ok && got != addressFromB {
		t.Fatalf("accounts[%q].address = %s does not match the phrase (%s); the file carries two different identities",
			w.SigName, got, addressFromB)
	}
	if got, ok := storedArchive[w.SigName2]; ok && got != w.Account2.Address.GetHex() {
		t.Fatalf("accounts[%q].address = %s does not match the phrase (%s)",
			w.SigName2, got, w.Account2.Address.GetHex())
	}
	for scheme, addr := range storedArchive {
		if addr == addressFromA {
			t.Fatalf("the archive still holds the pre-restore identity under key %q (%s)", scheme, addr)
		}
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 230, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("the restored wallet does not load: %v", err)
	}
	if loaded.MainAddress.GetHex() != addressFromB {
		t.Fatalf("after reloading, MainAddress = %s, expected %s (the identity from the restored phrase)",
			loaded.MainAddress.GetHex(), addressFromB)
	}
	if loaded.Account1.Address.GetHex() != addressFromB {
		t.Fatalf("after reloading, Account1 = %s, expected %s",
			loaded.Account1.Address.GetHex(), addressFromB)
	}
	phrase, err := loaded.GetMnemonicWords(true)
	if err != nil {
		t.Fatalf("the restored phrase is not available after loading: %v", err)
	}
	if strings.Join(strings.Fields(phrase), " ") != strings.Join(strings.Fields(string(phraseB)), " ") {
		t.Fatal("the stored phrase is not the one the wallet was restored from")
	}
}

// TestSchemeChangeSeedOutranksStaleArchive covers the load path directly: a
// seeded wallet whose archive holds a FOREIGN key for the scheme the chain just
// voted in must derive from its phrase and ignore the archive entry. Deriving is
// self-verifying — the same phrase always yields the same key — so an archive
// entry that disagrees can only be stale or foreign.
func TestSchemeChangeSeedOutranksStaleArchive(t *testing.T) {
	phraseA, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	phraseB, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	w := newSeedTestWallet(t, 231)
	if err := w.SetMnemonic(phraseA); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)

	withSchemeChangeTarget(t)

	// What the phrase derives for the new scheme — the only correct answer.
	expected, err := GenerateNewAccountFromSeed(*w, schemeChangeTarget, true)
	if err != nil {
		t.Fatal(err)
	}

	// Plant a foreign archive entry for the new scheme: same wallet (so it is
	// encrypted under this wallet's key and would load cleanly), different
	// phrase. This is what a restore used to leave behind.
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

	// The identity does not move when the SCHEME changes: public keys are
	// registered under MainAddress and the operator's stake is held against it,
	// so following the new scheme key here would orphan both.
	originalMain := w.MainAddress.GetHex()

	loaded, err := LoadJSONFromDir(w.HomePath, 231, "test-password-123", schemeChangeTarget, w.SigName2)
	if err != nil {
		t.Fatalf("seeded wallet failed a scheme change it should have derived: %v", err)
	}
	if loaded.Account1.Address.GetHex() != expected.Address.GetHex() {
		t.Fatalf("Account1 = %s, expected the one derived from the phrase %s (an archive entry %s was used instead)",
			loaded.Account1.Address.GetHex(), expected.Address.GetHex(), foreign.Address.GetHex())
	}
	if loaded.MainAddress.GetHex() != originalMain {
		t.Fatalf("MainAddress moved to %s after a scheme change; it must stay %s, the identity keys are registered under",
			loaded.MainAddress.GetHex(), originalMain)
	}
	_, archive := readStoredAccountAddresses(t, w.HomePath, 231)
	if got, ok := archive[schemeChangeTarget]; ok && got == foreign.Address.GetHex() {
		t.Fatalf("a foreign archive entry for %q survived loading (%s)", schemeChangeTarget, got)
	}
}

// TestLegacyWalletSchemeChangeStillUsesArchive guards the reordering done for
// I1: the seed is consulted BEFORE the per-scheme archive, but for a wallet with
// no seed the archive is still the only source there is, and taking it must keep
// working — otherwise a phrase-less wallet that legitimately holds a key for the
// new scheme would be refused as if it had none.
func TestLegacyWalletSchemeChangeStillUsesArchive(t *testing.T) {
	w := newSeedTestWallet(t, 232)
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

	withSchemeChangeTarget(t)

	archived, err := GenerateNewAccount(*w, schemeChangeTarget)
	if err != nil {
		t.Fatal(err)
	}
	w.Accounts[schemeChangeTarget] = archived
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 232, "test-password-123", schemeChangeTarget, w.SigName2)
	if err != nil {
		t.Fatalf("a phrase-less wallet with an archived key failed to load after a scheme change: %v", err)
	}
	if loaded.Account1.Address.GetHex() != archived.Address.GetHex() {
		t.Fatalf("Account1 = %s, expected the archived key %s",
			loaded.Account1.Address.GetHex(), archived.Address.GetHex())
	}
}

package wallet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/qwid-org/qwid-node/logger"

	"io"
	"sync"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// Argon2id key-derivation parameters (CW-C3). Tuned for interactive wallet
// unlock: ~64 MiB memory makes GPU/ASIC brute-forcing expensive while staying
// fast enough for a single unlock.
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // KiB => 64 MiB
	argon2Threads = 4
	argon2KeyLen  = 32
	kdfSaltLen    = 16
)

var globalMutex sync.RWMutex

type Account struct {
	secretKey          common.PrivKey
	EncryptedSecretKey []byte         `json:"encrypted_secret_key"`
	PublicKey          common.PubKey  `json:"public_key"`
	Address            common.Address `json:"address"`
	signer             oqs.Signature
}

// Wallet Structure map of Height and wallet which was change
type Wallet struct {
	// password holds the plaintext passphrase in a zeroable []byte (not an
	// immutable string) so Wipe() can clear it from memory (CW-C4). It is
	// retained because wallet reload (GetCurrentWallet) and legacy-format
	// decryption re-derive keys from it.
	password      []byte
	passwordBytes []byte
	// seed is the 64-byte BIP39 seed derived from the recovery phrase. Present
	// only while the wallet is unlocked; Wipe() zeroes it.
	seed []byte
	// EncryptedMnemonic holds the recovery phrase under the same AES-256-GCM /
	// Argon2id key as the secret keys. The phrase is stored rather than the seed
	// because PBKDF2 is one-way: from a seed the words cannot be shown again.
	// omitempty keeps pre-existing wallet files byte-identical.
	EncryptedMnemonic []byte             `json:"encrypted_mnemonic,omitempty"`
	Iv                []byte             `json:"iv"`
	KdfSalt           []byte             `json:"kdf_salt"`
	HomePath          string             `json:"home_path"`
	WalletNumber      uint8              `json:"wallet_number"`
	MainAddress       common.Address     `json:"main_address"`
	SigName           string             `json:"sig_name"`
	SigName2          string             `json:"sig_name_2"`
	Account1          Account            `json:"account_1"`
	Account2          Account            `json:"account_2"`
	Accounts          map[string]Account `json:"accounts"`
}

var activeWallet *Wallet

type AnyWallet interface {
	GetWallet() Wallet
}

func InitActiveWallet(walletNumber uint8, password string, sigName, sigName2 string) {
	var err error
	w, err := LoadJSON(walletNumber, password, sigName, sigName2)
	activeWallet = w
	if err != nil {
		logger.GetLogger().Println("wrong password", err)
		os.Exit(1)
	}
	if activeWallet == nil {
		logger.GetLogger().Println("failed to load wallet")
		os.Exit(1)
	}
}

func GetCurrentWallet(sigName, sigName2 string) (*Wallet, error) {
	aw := GetActiveWallet()
	var err error
	w, err := LoadJSON(aw.WalletNumber, string(aw.password), sigName, sigName2)
	currentWallet := w
	if err != nil {
		logger.GetLogger().Println("wrong password: GetCurrentWallet")
		return nil, err
	}
	if currentWallet == nil {
		logger.GetLogger().Println("failed to load wallet: GetCurrentWallet")
		return nil, fmt.Errorf("failed to load wallet: GetCurrentWallet")
	}
	return currentWallet, nil
}

func (w *Wallet) SetPassword(password string) {
	(*w).password = []byte(password)
	(*w).passwordBytes = w.deriveKey(password)
}

// VerifyPassword reports whether password matches this wallet's password, using
// a constant-time comparison of the Argon2id-derived keys. Used to re-authenticate
// before sensitive operations such as revealing the mnemonic (WH-C5).
func (w *Wallet) VerifyPassword(password string) bool {
	if len(w.passwordBytes) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(w.passwordBytes, w.deriveKey(password)) == 1
}

// Wipe zeroes the plaintext password and derived key in memory. Call it when a
// wallet is no longer needed (e.g. session end) to limit exposure in core dumps
// or swap (CW-C4, CW-H2).
func (w *Wallet) Wipe() {
	for i := range w.password {
		w.password[i] = 0
	}
	for i := range w.passwordBytes {
		w.passwordBytes[i] = 0
	}
	for i := range w.seed {
		w.seed[i] = 0
	}
	w.seed = nil
	w.password = nil
	w.passwordBytes = nil
	// CW-H2: cleanse the live post-quantum secret keys. signer.Clean() runs
	// OQS_MEM_cleanse over the retained secret-key bytes (which alias
	// secretKey.ByteValue) and frees the C handle; it is nil-safe on an account
	// that never initialized (e.g. paused encryption). Cleanse() zeroes the
	// PrivKey.ByteValue slice as defense-in-depth.
	w.Account1.signer.Clean()
	w.Account2.signer.Clean()
	w.Account1.secretKey.Cleanse()
	w.Account2.secretKey.Cleanse()
}

// deriveKey derives the AES-256 key from the password using Argon2id and the
// wallet's stored salt (CW-C3). If the wallet has no salt yet (new wallet or a
// legacy wallet being migrated), a fresh random salt is generated and stored so
// the next StoreJSON persists it.
func (w *Wallet) deriveKey(password string) []byte {
	if len(w.KdfSalt) == 0 {
		w.KdfSalt = newKdfSalt()
	}
	return argon2Key(password, w.KdfSalt)
}

// MinPasswordLength is the minimum acceptable password length for new wallets
// and password changes (CW-M7).
const MinPasswordLength = 8

// ValidatePasswordStrength rejects passwords that are too weak. It is enforced
// on wallet creation and password changes; it is deliberately NOT applied when
// loading an existing wallet, so pre-existing wallets are never locked out.
func ValidatePasswordStrength(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	return nil
}

// argon2Key derives a 32-byte key from a password and an explicit salt.
func argon2Key(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

func newKdfSalt() []byte {
	salt := make([]byte, kdfSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}
	return salt
}

func GetActiveWallet() *Wallet {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	return activeWallet
}

func SetActiveWallet(w *Wallet) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	activeWallet = w
}

func (w *Wallet) ShowInfo() string {

	// CW-H4: do not emit private-key metadata (lengths). Public keys and
	// addresses are public information; secret-key details are omitted and the
	// result is returned to the caller rather than printed to stdout.
	s := fmt.Sprintln("Beginning of public key:", w.Account1.PublicKey.GetHex()[:10])
	s += fmt.Sprintln("Address:", w.Account1.Address.GetHex())
	s += fmt.Sprintln("Beginning of public key 2:", w.Account2.PublicKey.GetHex()[:10])
	s += fmt.Sprintln("Address 2:", w.Account2.Address.GetHex())
	s += fmt.Sprintln("MainAddress:", w.MainAddress.GetHex())
	s += fmt.Sprintln("Wallet location", w.HomePath)
	s += fmt.Sprintln("Wallet Number", w.WalletNumber)
	return s
}

// legacyPasswordToByte derives the AES key the way pre-security-fix wallets did
// (a single SHAKE-256 pass, no KDF). Used only by the legacy AES-CTR read path so
// old wallet files still decrypt; never use it for new encryption.
func legacyPasswordToByte(password string) []byte {
	sh := make([]byte, 32)
	sha3.ShakeSum256(sh, []byte(password))
	return sh
}

func (w *Wallet) GetSigName(primary bool) string {
	if primary {
		return w.SigName
	} else {
		return w.SigName2
	}
}

func EmptyWallet(walletNumber uint8, sigName, sigName2 string) Wallet {
	homePath, err := os.UserHomeDir()
	if err != nil {
		logger.GetLogger().Fatal(err)
	}

	return Wallet{
		password:      nil,
		passwordBytes: nil,
		Iv:            nil,
		Account1:      EmptyAccount(),
		Account2:      EmptyAccount(),
		SigName:       sigName,
		SigName2:      sigName2,
		Accounts:      map[string]Account{},
		MainAddress:   common.Address{},
		HomePath:      homePath + common.DefaultWalletHomePath + strconv.Itoa(int(walletNumber)),
		WalletNumber:  walletNumber,
	}
}

func EmptyAccount() Account {
	return Account{
		secretKey:          common.PrivKey{},
		EncryptedSecretKey: nil,
		PublicKey:          common.PubKey{},
		Address:            common.Address{},
		signer:             oqs.Signature{},
	}
}

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
	// Zero any previously derived seed before replacing it, so a phrase change
	// (or a second SetMnemonic call) never leaves the old seed lingering in memory.
	ZeroBytes(w.seed)
	w.seed = seed
	w.EncryptedMnemonic = enc
	return nil
}

// HasSeed reports whether this wallet can derive keys from a recovery phrase.
// Wallets created before this feature return false and keep their previous,
// random key generation. This only checks presence, not integrity: a struct
// copy taken concurrently with Wipe() can observe a zeroed backing array with
// a non-zero length (slices share their backing array across a value copy).
// GenerateNewAccountFromSeed guards against that case before deriving
// anything from the seed.
func (w *Wallet) HasSeed() bool {
	return len(w.seed) > 0
}

// bip39SeedLength is the exact size of the seed SeedFromMnemonic produces
// (standard BIP39: PBKDF2-HMAC-SHA512, 64-byte output).
const bip39SeedLength = 64

// isAllZero reports whether every byte of b is zero. Used to detect a seed
// that has been wiped out from under a stale struct copy (see HasSeed).
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
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
	// A struct copy of Wallet taken just before the original's Wipe() runs
	// shares the same seed backing array; Wipe() zeroing it in place would
	// otherwise leave this copy reporting HasSeed()==true over an all-zero
	// seed, silently deriving keys from no entropy at all.
	if len(w.seed) != bip39SeedLength || isAllZero(w.seed) {
		return Account{}, fmt.Errorf("wallet seed is invalid (wrong length or zeroed out); reload the wallet or restore it from its recovery phrase")
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

func GenerateNewAccount(w Wallet, sigName string) (Account, error) {
	if len(w.password) < 1 {
		return Account{}, fmt.Errorf("password cannot be empty")
	}

	var signer oqs.Signature

	// ignore potential errors everywhere
	err := signer.Init(sigName, nil)
	if err != nil {
		return Account{}, err
	}
	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		return Account{}, err
	}

	acc := EmptyAccount()
	err = acc.PublicKey.Init(pubKey, w.MainAddress)
	if err != nil {
		return Account{}, err
	}
	acc.Address = acc.PublicKey.GetAddress()

	err = acc.secretKey.Init(signer.ExportSecretKey(), acc.Address, false)
	if err != nil {
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

func (w *Wallet) AddNewEncryptionToActiveWallet(sigName string, primary bool) error {

	if len(w.password) < 1 {
		return fmt.Errorf("password cannot be empty")
	}

	var signer oqs.Signature
	ew := EmptyWallet(w.WalletNumber, sigName, sigName)
	// ignore potential errors everywhere
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
		// Refuse, exactly as the load path does (loadWalletFromStruct's
		// scheme-change branches). Generating a random key here would mint a
		// brand-new, unstaked identity and — because the caller archives it with
		// StoreJSON — persist it, so the load path's refusal would never get the
		// chance to fire on the next restart: it would find the archived entry,
		// take it, and repoint MainAddress at it. The staked identity would be
		// replaced anyway, silently, which is precisely what the refusal exists
		// to prevent. Failing loudly here leaves the node following the chain
		// with no key for the new scheme until the operator intervenes.
		return fmt.Errorf("the network switched signature scheme to %q, but this wallet has no recovery phrase to derive a %q key from; "+
			"generating a random key would silently replace this wallet's staked identity with a new, unstaked one. "+
			"Restore this wallet from its 24-word recovery phrase (preferred), or from a wallet-file backup that already contains a %q key. "+
			"Until then this node cannot produce with %q",
			sigName, sigName, sigName, sigName)
	}
	mainAddress, err := common.PubKeyToAddress(pubKey, primary)
	if err != nil {
		return err
	}
	if primary {
		err = w.Account1.PublicKey.Init(pubKey, mainAddress)
		if err != nil {
			return err
		}
		(*w).Account1.Address = w.Account1.PublicKey.GetAddress()
		err = w.Account1.secretKey.Init(signer.ExportSecretKey(), w.Account1.Address, true)
		if err != nil {
			return err
		}
		(*w).Account1.signer = signer
		(*w).HomePath = ew.HomePath
	} else {
		err = w.Account2.PublicKey.Init(pubKey, mainAddress)
		if err != nil {
			return err
		}
		(*w).Account2.Address = w.Account2.PublicKey.GetAddress()
		err = w.Account2.secretKey.Init(signer.ExportSecretKey(), w.Account2.Address, false)
		if err != nil {
			return err
		}
		(*w).Account2.signer = signer
	}

	logger.GetLogger().Println(signer.Details())
	return nil
}

func GenerateNewIv() []byte {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	return iv
}

// encrypt encrypts v with AES-256-GCM. GCM is an authenticated (AEAD) mode, so
// ciphertext tampering is detected on decryption (fixes CW-C1). A fresh random
// nonce is generated for every call and prepended to the output, so no two
// encryptions ever reuse a nonce (fixes CW-C2). Output layout: nonce || ciphertext+tag.
// encryptWithKey encrypts v under the given AES key without reading or mutating
// w.passwordBytes. CW-M3: lets ChangePasswordInPlace re-encrypt under the new key
// without toggling the shared field (which raced concurrent passwordBytes readers).
func (w *Wallet) encryptWithKey(key, v []byte) ([]byte, error) {
	cb, err := aes.NewCipher(key)
	if err != nil {
		logger.GetLogger().Println("Can not create AES function")
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(cb)
	if err != nil {
		logger.GetLogger().Println("Can not create GCM function")
		return []byte{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte{}, err
	}
	// Seal appends the ciphertext (including the auth tag) to nonce, so the
	// returned slice is nonce || ciphertext+tag.
	return gcm.Seal(nonce, nonce, v, nil), nil
}

func (w *Wallet) encrypt(v []byte) ([]byte, error) {
	return w.encryptWithKey(w.passwordBytes, v)
}

// decrypt reverses encrypt. New wallets are AES-256-GCM; if GCM authentication
// fails it falls back to the legacy AES-CTR format so wallet files written before
// this security fix still load. A wrong password fails both paths.
func (w *Wallet) decrypt(v []byte) ([]byte, error) {
	cb, err := aes.NewCipher(w.passwordBytes)
	if err != nil {
		logger.GetLogger().Println("Can not create AES function")
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(cb)
	if err != nil {
		logger.GetLogger().Println("Can not create GCM function")
		return []byte{}, err
	}
	ns := gcm.NonceSize()
	if len(v) >= ns {
		if plaintext, err := gcm.Open(nil, v[:ns], v[ns:], nil); err == nil {
			return plaintext, nil
		}
	}
	// Legacy fallback: wallets encrypted with the old AES-CTR scheme.
	return w.decryptLegacyCTR(v)
}

// decryptLegacyCTR decrypts wallet secret keys written with the pre-security-fix
// AES-CTR format (static wallet IV, "validationTag" prefix, dead 16-byte block).
// Kept only so existing wallets migrate transparently; new writes use GCM.
func (w *Wallet) decryptLegacyCTR(v []byte) ([]byte, error) {
	if len(v) < aes.BlockSize || len(w.Iv) == 0 {
		return nil, fmt.Errorf("wrong password")
	}
	cb, err := aes.NewCipher(legacyPasswordToByte(string(w.password)))
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(v)-aes.BlockSize)
	stream := cipher.NewCTR(cb, w.Iv)
	stream.XORKeyStream(plaintext, v[aes.BlockSize:])
	if len(plaintext) < len(common.ValidationTag) ||
		!bytes.Equal(plaintext[:len(common.ValidationTag)], []byte(common.ValidationTag)) {
		return nil, fmt.Errorf("wrong password")
	}
	return plaintext[len(common.ValidationTag):], nil
}

// GetMnemonicWords returns the recovery phrase this wallet was created from.
//
// Note the direction: the phrase is the input the keys were derived from, not an
// encoding of a key. Encoding a post-quantum secret key as a phrase is
// impossible (Falcon-512 is ~1281 bytes against BIP39's 64), which is why
// wallets created before this feature have no phrase and never can (CW-M2).
func (w *Wallet) GetMnemonicWords(primary bool) (string, error) {
	if len(w.passwordBytes) == 0 {
		return "", fmt.Errorf("set the wallet password before the recovery phrase")
	}
	if len(w.EncryptedMnemonic) == 0 {
		return "", fmt.Errorf("this wallet was created without a recovery phrase; " +
			"use the encrypted wallet-file backup instead")
	}
	mnemonic, err := w.decrypt(w.EncryptedMnemonic)
	if err != nil {
		return "", fmt.Errorf("cannot decrypt the recovery phrase: %w", err)
	}
	// string(mnemonic) copies, so the decrypted plaintext can be zeroed right
	// after — same pattern as every other decrypt site in this file (wallet.go
	// loadKeys / ChangePassword / ChangePasswordInPlace).
	words := string(mnemonic)
	ZeroBytes(mnemonic)
	// The phrase covers every scheme and both roles, so `primary` does not select
	// between two phrases — it is kept only so existing callers still compile.
	_ = primary
	return words, nil
}

// RestoreSecretKeyFromMnemonic rebuilds the wallet's keys — both roles, every
// scheme — from a recovery phrase. One phrase covers the whole wallet, so a
// partial restore (only Account1 or only Account2) would leave the stored
// phrase claiming to back up a wallet it cannot actually reconstruct: the
// phrase GetMnemonicWords hands back afterwards must reconstruct BOTH
// accounts, not just the one the caller happened to ask for. `primary` is
// accepted but ignored, for the same reason GetMnemonicWords ignores it —
// existing callers keep compiling; Task 7 updates them to drop the parameter.
// This also makes repeated calls idempotent regardless of the primary value
// passed, which matters because cmd/gui/qtwidgets/wallet.go calls this twice
// in a row (once with primary=true, once with primary=false) to restore one
// wallet.
//
// The whole operation is atomic, including against a derivation failure, not
// just a bad phrase: the phrase is validated and encrypted, and both accounts
// are derived, on a scratch copy of the wallet before anything on w is
// touched. w.seed, w.EncryptedMnemonic, w.Account1, w.Account2 and
// w.MainAddress are only written once every step above has succeeded — so a
// bad phrase, or a derivation failure partway through (for example the
// network having voted in a signature scheme this build of liboqs does not
// support — loadKeys already has to handle exactly that case, see its "has
// neither a stored key ... nor a recovery phrase" error path), leaves w
// exactly as it was. The stored phrase and the keys it backs can never
// disagree.
func (w *Wallet) RestoreSecretKeyFromMnemonic(mnemonic string, primary bool) error {
	_ = primary
	if len(w.passwordBytes) == 0 {
		return fmt.Errorf("set the wallet password before the recovery phrase")
	}
	seed, err := SeedFromMnemonic([]byte(mnemonic))
	if err != nil {
		return err
	}
	enc, err := w.encrypt([]byte(mnemonic))
	if err != nil {
		ZeroBytes(seed)
		return err
	}

	// Derive both accounts on a scratch copy that carries the NEW seed. Wallet
	// is passed by value into GenerateNewAccountFromSeed, and neither it nor
	// DeriveKeySeed mutates the seed slice they're given, so nothing here can
	// touch w — if either derivation fails, w has not been written to at all.
	scratch := *w
	scratch.seed = seed
	acc1, err := GenerateNewAccountFromSeed(scratch, w.SigName, true)
	if err != nil {
		ZeroBytes(seed)
		return err
	}
	acc2, err := GenerateNewAccountFromSeed(scratch, w.SigName2, false)
	if err != nil {
		ZeroBytes(seed)
		return err
	}

	// Every step above succeeded — commit atomically.
	ZeroBytes(w.seed)
	w.seed = seed
	w.EncryptedMnemonic = enc
	w.Account1 = acc1
	w.Account2 = acc2
	w.MainAddress = w.Account1.Address
	// Rebuild the per-scheme key archive from scratch. Whatever was in it before
	// belongs to the identity this restore just replaced (or to another wallet
	// entirely) and the new phrase does not derive it; leaving it would put two
	// disagreeing identities in the same file, and the load path would then have
	// to choose between them. The archive now holds exactly the two accounts the
	// phrase derives — a key for any other scheme is re-derived from the seed on
	// demand, which is why dropping the rest loses nothing.
	// (Written secondary-first so that if a chain ever runs the same scheme in
	// both roles, the single surviving entry is the primary one — Account1 is
	// the wallet's identity.)
	w.Accounts = map[string]Account{w.SigName2: acc2}
	w.Accounts[w.SigName] = acc1
	// Realigns role metadata (Primary flags, PublicKey.MainAddress) across both
	// accounts with the new MainAddress — the same fix-up loadKeys applies after
	// reading a wallet off disk, so a restored wallet matches its reloaded form.
	w.normalizeAccountRoles()
	return nil
}

// setArchivedAccount records acc as the per-scheme archive entry for sigName,
// replacing whatever was there. Called after deriving a key from the seed so the
// archive is refreshed with the entry the phrase actually derives instead of
// keeping a stale one next to it; the map is created if the wallet was
// unmarshalled from JSON without an "accounts" object (nil map).
func (w *Wallet) setArchivedAccount(sigName string, acc Account) {
	if w.Accounts == nil {
		w.Accounts = map[string]Account{}
	}
	w.Accounts[sigName] = acc
}

// normalizeAccountRoles sets the primary/secondary role metadata (the Primary
// flags and PublicKey.MainAddress) consistently across the wallet's two accounts:
// Account1 is primary, Account2 secondary. This mirrors the canonical state that
// loadKeys produces after loading a wallet from disk, so a freshly generated
// wallet equals its own reloaded form (OB-122). GenerateNewAccount cannot set
// these at creation time (w.MainAddress is unknown when Account1 is generated,
// and accounts are created with primary=false), which is why the persist path
// normalizes them here. secretKey is not persisted, but its Primary flag is part
// of the in-memory identity compared by callers, so it is normalized too.
func (w *Wallet) normalizeAccountRoles() {
	w.MainAddress.Primary = true
	w.Account1.Address.Primary = true
	w.Account2.Address.Primary = false
	w.Account1.PublicKey.Address.Primary = true
	w.Account2.PublicKey.Address.Primary = false
	w.Account1.PublicKey.Primary = true
	w.Account2.PublicKey.Primary = false
	w.Account1.PublicKey.MainAddress = w.MainAddress
	w.Account2.PublicKey.MainAddress = w.MainAddress
	w.Account1.secretKey.Primary = true
	w.Account2.secretKey.Primary = false
}

func (w *Wallet) StoreJSON() error {
	if w.GetSecretKey().GetBytes() == nil {
		return fmt.Errorf("you need load wallet first")
	}

	// Create the wallet file path
	walletFile := filepath.Join(w.HomePath, "wallet"+strconv.Itoa(int(w.WalletNumber)))
	logger.GetLogger().Println("walletFile:", walletFile+".json")

	se, err := w.encrypt(w.Account1.secretKey.GetBytes())
	if err != nil {
		logger.GetLogger().Println(err)
		return err
	}

	w.Account1.EncryptedSecretKey = make([]byte, len(se))
	copy(w.Account1.EncryptedSecretKey, se)

	se, err = w.encrypt(w.Account2.secretKey.GetBytes())
	if err != nil {
		logger.GetLogger().Println(err)
		return err
	}

	w.Account2.EncryptedSecretKey = make([]byte, len(se))
	copy(w.Account2.EncryptedSecretKey, se)

	// Archive the two live accounts under their scheme names, if the archive does
	// not already carry an entry for them. Done AFTER the re-encryption above so
	// the archived struct carries the ciphertext just written, not the previous
	// one. setArchivedAccount also creates the map, which a wallet unmarshalled
	// from a JSON file without an "accounts" object does not have (a nil map here
	// used to panic on assignment).
	if _, ok := w.Accounts[w.SigName]; !ok {
		logger.GetLogger().Println("wallet carried no archive entry for the primary scheme; adding it")
		w.setArchivedAccount(w.SigName, w.Account1)
	}
	if _, ok := w.Accounts[w.SigName2]; !ok {
		logger.GetLogger().Println("wallet carried no archive entry for the secondary scheme; adding it")
		w.setArchivedAccount(w.SigName2, w.Account2)
	}

	// Refresh the per-scheme key archive.
	//
	// OB-55. This loop used to do, for EVERY entry:
	//
	//	se, _ := w.encrypt(v.secretKey.GetBytes())
	//	copy(w.Accounts[k].EncryptedSecretKey, se)
	//
	// which silently destroyed the archive of any wallet loaded from disk, on
	// every single save. Two mistakes compounded:
	//
	//  1. Account.secretKey is unexported, so it is never marshalled and never
	//     restored: for an entry read back from the wallet file it is the zero
	//     value. Encrypting it produced a ~28-byte GCM blob of nothing at all,
	//     not the key.
	//  2. copy() writes min(len(dst), len(src)) bytes, so those 28 bytes were
	//     spliced over the HEAD of the real ~1300-byte ciphertext, leaving the
	//     tail in place. The result authenticates against nothing and can never
	//     be decrypted again, by any password. (The damage was invisible for
	//     entries created in the same session, where secretKey is live and the
	//     two blobs happen to be the same length, so copy() was a full
	//     overwrite — which is why this survived so long.)
	//
	// copy() was used because a field of a map value is not addressable in Go
	// (w.Accounts[k].EncryptedSecretKey = se does not compile). The fix is to
	// take the struct out, change it, and put it back.
	//
	// The empty-secretKey case must not be re-encrypted at all: StoreJSON never
	// changes the password, so an entry read off disk already holds correct
	// ciphertext under the CURRENT key and the right thing to do with it is
	// nothing. Re-encrypting under a *different* password is exclusively
	// ChangePassword's and ChangePasswordInPlace's job, and both do it by
	// decrypting under the old key first — the empty secretKey is no substitute.
	for k, v := range w.Accounts {
		sk := v.secretKey.GetBytes()
		if len(sk) == 0 {
			// Loaded from disk and never unlocked into this entry: leave the
			// stored ciphertext exactly as it is.
			continue
		}
		se, err := w.encrypt(sk)
		if err != nil {
			logger.GetLogger().Println(err)
			return err
		}
		v.EncryptedSecretKey = se
		w.Accounts[k] = v
	}

	// EncryptedMnemonic is deliberately NOT re-encrypted here. It is only ever
	// correct to re-encrypt it against a *specific* old/new key pair, which only
	// ChangePassword and ChangePasswordInPlace know; StoreJSON only ever sees the
	// current password, so trying to "refresh" the encryption here by decrypting
	// under the current key and re-encrypting under the same current key is pure
	// churn on the normal path. Worse, during ChangePasswordInPlace's transition
	// window w.passwordBytes is already the *new* key while EncryptedMnemonic is
	// still under the *old* one, so a decrypt attempted here would fail, and a
	// swallowed failure used to persist an unopenable phrase permanently. Both
	// password-change functions now re-encrypt EncryptedMnemonic explicitly
	// before calling StoreJSON, so by the time we get here it is already correct
	// under the current key (or absent, for legacy wallets).

	// OB-122: normalize account role metadata before persisting so a freshly
	// generated wallet is identical to its own reloaded form. GenerateNewAccount
	// cannot set these for Account1 (w.MainAddress is not yet known when Account1
	// is created, and it is created with the secondary/primary=false role), so
	// without this a fresh wallet diverges from loadKeys' normalized output on
	// PublicKey.MainAddress and the primary/secondary flags. MainAddress and the
	// Primary flags are part of the pubkey/tx identity. Loaded wallets already
	// normalize on load, so this does not change on-wire behavior for existing
	// wallets — it only makes the pre-store in-memory/persisted state consistent.
	w.normalizeAccountRoles()

	// Marshal the wallet to JSON
	wm, err := json.MarshalIndent(&w, "", "    ")
	if err != nil {
		logger.GetLogger().Println(err)
		return err
	}
	// Create wallet directory if it doesn't exist (0700: owner-only, CW-H3)
	if err := os.MkdirAll(w.HomePath, 0700); err != nil {
		return err
	}

	// Write the wallet to the JSON file
	if err := os.WriteFile(walletFile+".json", wm, 0600); err != nil {
		return err
	}

	return nil
}

// LoadJSONFromDir loads a wallet from a custom directory path.
func LoadJSONFromDir(walletDir string, walletNumber uint8, password string, sigName, sigName2 string) (*Wallet, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	walletFile := filepath.Join(walletDir, "wallet"+strconv.Itoa(int(walletNumber))+".json")
	data, err := os.ReadFile(walletFile)
	if err != nil {
		return nil, err
	}
	var w Wallet
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, err
	}
	w.HomePath = walletDir
	w.WalletNumber = walletNumber
	return loadWalletFromStruct(&w, walletDir, password, sigName, sigName2)
}

// LoadJSON if height >= 0 current wallet will be replaced by latest but not larger than height
func LoadJSON(walletNumber uint8, password string, sigName, sigName2 string) (*Wallet, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	ew := EmptyWallet(walletNumber, sigName, sigName2)
	homePath := ew.HomePath

	walletFile := filepath.Join(homePath, "wallet"+strconv.Itoa(int(walletNumber))+".json")
	data, err := os.ReadFile(walletFile)
	if err != nil {
		return nil, err
	}
	var w Wallet
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, err
	}
	return loadWalletFromStruct(&w, homePath, password, sigName, sigName2)
}

func loadWalletFromStruct(w *Wallet, homePath, password, sigName, sigName2 string) (*Wallet, error) {
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

	if !common.IsPaused() && w.SigName != sigName {
		w.SigName = sigName
		// The seed outranks the per-scheme key archive, and is consulted FIRST.
		// For a seeded wallet the phrase defines the identity: derivation is
		// self-verifying (the same phrase always yields the same key), so an
		// archive entry that disagrees is by definition stale (written before a
		// restore) or foreign (copied in from another wallet). Taking the
		// archive first, as this used to, meant that after
		// RestoreSecretKeyFromMnemonic the wallet loaded its PRE-restore
		// identity back — silently, and with MainAddress repointed at it.
		if w.HasSeed() {
			acc, err := GenerateNewAccountFromSeed(*w, sigName, true)
			if err != nil {
				return nil, err
			}
			w.Account1 = acc
			copy(w.Account1.EncryptedSecretKey[:], acc.EncryptedSecretKey[:])
			w.setArchivedAccount(sigName, acc)
		} else if a, ok := w.Accounts[sigName]; ok {
			w.Account1 = a
			copy(w.Account1.EncryptedSecretKey[:], a.EncryptedSecretKey[:])
		} else {
			// No stored key for the new scheme and no recovery phrase to derive
			// one from: generating a random key here would silently hand this
			// wallet a brand-new, unstaked identity (loadWalletFromStruct later
			// overwrites MainAddress from Account1.Address). Refuse instead.
			// The recovery phrase is the reliable route (StoreJSON's per-scheme
			// key archive can itself go stale across reloads, a separate,
			// pre-existing issue), so lead with that and mention a file backup
			// only as a secondary option.
			return nil, fmt.Errorf("the network switched primary signature scheme to %q, but this wallet has neither a stored key for %q nor a recovery phrase to derive one from; restore this wallet from its 24-word recovery phrase (preferred), or from a wallet-file backup taken after a %q key was already present", sigName, sigName, sigName)
		}
	}
	if !common.IsPaused2() && w.SigName2 != sigName2 {
		w.SigName2 = sigName2
		// Seed first — see the matching comment in the primary branch above.
		if w.HasSeed() {
			acc, err := GenerateNewAccountFromSeed(*w, sigName2, false)
			if err != nil {
				return nil, err
			}
			w.Account2 = acc
			copy(w.Account2.EncryptedSecretKey[:], acc.EncryptedSecretKey[:])
			w.setArchivedAccount(sigName2, acc)
		} else if a, ok := w.Accounts[sigName2]; ok {
			w.Account2 = a
			copy(w.Account2.EncryptedSecretKey[:], a.EncryptedSecretKey[:])
		} else {
			// See the matching comment in the primary branch above.
			return nil, fmt.Errorf("the network switched secondary signature scheme to %q, but this wallet has neither a stored key for %q nor a recovery phrase to derive one from; restore this wallet from its 24-word recovery phrase (preferred), or from a wallet-file backup taken after a %q key was already present", sigName2, sigName2, sigName2)
		}
	}

	// Try to init Account1 - always try, tolerate failure if encryption is paused
	account1OK := false
	if len(w.Account1.EncryptedSecretKey) > 0 {
		ds, err := w.decrypt(w.Account1.EncryptedSecretKey)
		if err == nil {
			var signer oqs.Signature
			err = signer.Init(w.SigName, ds)
			if err == nil {
				ds = ds[:signer.Details().LengthSecretKey]
				err = signer.Init(w.SigName, ds)
				if err == nil {
					w.Account1.signer = signer
					cnz := CountNonZeroBytes(ds)
					logger.GetLogger().Println("cnz:", cnz)
					err = w.Account1.secretKey.Init(ds, w.Account1.Address, true)
					if err == nil {
						account1OK = true
					}
				}
			}
		}
		if !account1OK {
			if !common.IsPaused() {
				logger.GetLogger().Println("Account1 init failed:", err)
				return nil, fmt.Errorf("Account1 init failed: %v", err)
			}
			logger.GetLogger().Println("Account1 init failed (1st encryption paused, OK):", err)
		}
	} else if !common.IsPaused() {
		return nil, fmt.Errorf("Account1 encrypted secret key is empty")
	}

	// Try to init Account2 - always try, tolerate failure if encryption is paused
	account2OK := false
	if len(w.Account2.EncryptedSecretKey) > 0 {
		ds, err := w.decrypt(w.Account2.EncryptedSecretKey)
		if err == nil {
			var signer2 oqs.Signature
			err = signer2.Init(w.SigName2, ds)
			if err == nil {
				ds = ds[:signer2.Details().LengthSecretKey]
				err = signer2.Init(w.SigName2, ds)
				if err == nil {
					w.Account2.signer = signer2
					cnz := CountNonZeroBytes(ds)
					logger.GetLogger().Println("cnz:", cnz)
					err = w.Account2.secretKey.Init(ds, w.Account2.Address, false)
					if err == nil {
						account2OK = true
					}
				}
			}
		}
		if !account2OK {
			if !common.IsPaused2() {
				logger.GetLogger().Println("Account2 init failed:", err)
				return nil, fmt.Errorf("Account2 init failed: %v", err)
			}
			logger.GetLogger().Println("Account2 init failed (2nd encryption paused, OK):", err)
		}
	} else if !common.IsPaused2() {
		return nil, fmt.Errorf("Account2 encrypted secret key is empty")
	}

	if !account1OK && !account2OK {
		return nil, fmt.Errorf("failed to load both accounts")
	}

	w.MainAddress.Primary = true
	w.Account1.Address.Primary = true
	w.Account2.Address.Primary = false
	w.Account1.PublicKey.Address.Primary = true
	w.Account2.PublicKey.Address.Primary = false
	w.Account1.PublicKey.Primary = true
	w.Account2.PublicKey.Primary = false

	// Ensure MainAddress is set correctly
	zeroAddr := make([]byte, common.AddressLength)
	account1HasAddress := !bytes.Equal(w.Account1.Address.GetBytes(), zeroAddr)
	account2HasAddress := !bytes.Equal(w.Account2.Address.GetBytes(), zeroAddr)

	if bytes.Equal(w.MainAddress.GetBytes(), zeroAddr) {
		// MainAddress is empty - set from whichever account has an address
		if account1HasAddress {
			w.MainAddress = w.Account1.Address
			logger.GetLogger().Println("MainAddress was empty, set from Account1.Address:", w.MainAddress.GetHex())
		} else if account2HasAddress {
			w.MainAddress = w.Account2.Address
			logger.GetLogger().Println("MainAddress was empty, set from Account2.Address:", w.MainAddress.GetHex())
		}
	} else if account1OK && account1HasAddress && !bytes.Equal(w.MainAddress.GetBytes(), w.Account1.Address.GetBytes()) {
		// Only update MainAddress from Account1 if Account1 actually initialized
		logger.GetLogger().Println("WARNING: MainAddress differs from Account1.Address!")
		logger.GetLogger().Println("MainAddress:", w.MainAddress.GetHex())
		logger.GetLogger().Println("Account1.Address:", w.Account1.Address.GetHex())
		w.MainAddress = w.Account1.Address
	}

	// Ensure MainAddress is set on PublicKeys (may be empty from older wallet JSON)
	w.Account1.PublicKey.MainAddress = w.MainAddress
	w.Account2.PublicKey.MainAddress = w.MainAddress

	w.Account1.secretKey.Address.Primary = true
	w.Account2.secretKey.Address.Primary = false
	w.Account1.secretKey.Primary = true
	w.Account2.secretKey.Primary = false

	w.HomePath = homePath
	w.StoreJSON()
	logger.GetLogger().Println("MainAddress:", w.MainAddress.GetHex())
	return w, nil
}

func (w *Wallet) ChangePassword(password, newPassword string) error {
	if w.passwordBytes == nil {
		return fmt.Errorf("you need load wallet first")
	}
	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}
	if !bytes.Equal(w.deriveKey(password), w.passwordBytes) {
		return fmt.Errorf("current password is not valid")
	}

	globalMutex.Lock()
	defer globalMutex.Unlock()

	// w2 gets its OWN copy of the per-scheme archive map. Handing it w.Accounts
	// directly (as this used to) meant the re-encryption below rewrote w's own
	// entries in place, so any failure between here and the reload at the end left
	// w holding new-key ciphertext while w.passwordBytes was still the old key. w
	// picks the archive back up from the reloaded wallet once the change has
	// actually landed on disk.
	accounts := make(map[string]Account, len(w.Accounts))
	for k, v := range w.Accounts {
		accounts[k] = v
	}
	w2 := Wallet{
		Iv:           w.Iv,
		HomePath:     w.HomePath,
		WalletNumber: w.WalletNumber,
		MainAddress:  w.MainAddress,
		SigName:      w.SigName,
		SigName2:     w.SigName2,
		Account1:     w.Account1,
		Account2:     w.Account2,
		Accounts:     accounts,
	}
	// Fresh Argon2id salt + key for the new password (KdfSalt left nil so
	// SetPassword generates one).
	w2.SetPassword(newPassword)

	// Re-encrypt the per-scheme key archive under the new key. OB-55: the write
	// back is an assignment, not `copy(w2.Accounts[k].EncryptedSecretKey, se)` —
	// see the long note in StoreJSON for why that truncating copy was destroying
	// archives.
	for k, v := range accounts {
		if err := func() error {
			var plain []byte
			if sk := v.secretKey.GetBytes(); len(sk) > 0 {
				// Unlocked in this session: authoritative, and needs no decrypt.
				// Never cleansed here — it is the live key, not a copy.
				plain = sk
			} else {
				ds, err := w.decrypt(v.EncryptedSecretKey)
				if err != nil {
					// The password was already verified against w.passwordBytes
					// above, so this is not a wrong password: this one archived
					// blob cannot be opened. KEEP it, byte for byte, and carry
					// on with the password change.
					//
					// Keeping rather than dropping (the opposite of what is done
					// with EncryptedMnemonic just below) because the two are not
					// the same case. An unopenable phrase blob is provably dead
					// forever — it is verified against THE wallet key, the only
					// one there is — and leaving it on disk would advertise a
					// backup that does not exist. An archived key blob may simply
					// be under an older password (an earlier password change that
					// hit this same path), in which case its plaintext is still
					// recoverable offline from the file and deleting it here would
					// be the one irreversible act in an otherwise routine
					// operation. It is also inert: the archive is consulted only
					// on a chain scheme change, and a bad entry then fails loudly
					// at load ("Account1 init failed") rather than silently.
					//
					// Aborting is not an option either: that is exactly the
					// behaviour that has left wallets damaged by this very bug
					// unable to change their password at all.
					logger.GetLogger().Printf("WARNING: the archived key for signature scheme %q cannot be decrypted "+
						"with the current (verified correct) password: %v. It is being carried over UNCHANGED, still "+
						"under whatever key it was written with, so nothing is destroyed — but it will NOT open with "+
						"the new password. The wallet's live keys are unaffected and the password change continues. "+
						"If the network ever switches to %q this wallet will refuse to load until it is restored from "+
						"its recovery phrase or a wallet-file backup", k, err, k)
					return nil
				}
				defer func() { // CW-H2: cleanse the ephemeral decrypted key
					if len(ds) > 0 {
						oqs.MemCleanse(ds)
					}
				}()
				plain = ds
			}
			se, err := w2.encrypt(plain)
			if err != nil {
				logger.GetLogger().Println(err)
				return err
			}
			v.EncryptedSecretKey = se
			accounts[k] = v
			return nil
		}(); err != nil {
			return err
		}
	}

	// Re-encrypt Account1 and Account2 with the new password
	if len(w2.Account1.EncryptedSecretKey) > 0 {
		ds, err := w.decrypt(w.Account1.EncryptedSecretKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt Account1: %v", err)
		}
		defer func() { // CW-H2: cleanse the ephemeral decrypted key
			if len(ds) > 0 {
				oqs.MemCleanse(ds)
			}
		}()
		se, err := w2.encrypt(ds)
		if err != nil {
			return fmt.Errorf("failed to encrypt Account1: %v", err)
		}
		w2.Account1.EncryptedSecretKey = se
	}
	if len(w2.Account2.EncryptedSecretKey) > 0 {
		ds, err := w.decrypt(w.Account2.EncryptedSecretKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt Account2: %v", err)
		}
		defer func() { // CW-H2: cleanse the ephemeral decrypted key
			if len(ds) > 0 {
				oqs.MemCleanse(ds)
			}
		}()
		se, err := w2.encrypt(ds)
		if err != nil {
			return fmt.Errorf("failed to encrypt Account2: %v", err)
		}
		w2.Account2.EncryptedSecretKey = se
	}

	// Carry the recovery phrase across the password change, re-encrypted under
	// w2's new key. Without this, w2 (built field by field above) never gets an
	// EncryptedMnemonic at all and the phrase backup is silently lost forever
	// (PBKDF2 is one-way, so it can never be recovered from the seed).
	//
	// If it fails to decrypt under the just-verified-correct old password, the
	// phrase was already unrecoverable before this call (the load path already
	// degrades the same way — see Finding 4) and re-encrypting it under the new
	// password can never fix that. Aborting the whole password change here would
	// just be a dead end, contradicting the degrade-not-abort rule everywhere
	// else. w2.EncryptedMnemonic is left at its zero value (nil), dropping the
	// blob rather than carrying forward ciphertext now known to never decrypt:
	// keeping it would leave a field on disk that looks like a phrase backup
	// but provably isn't one.
	if len(w.EncryptedMnemonic) > 0 {
		mnemonic, err := w.decrypt(w.EncryptedMnemonic)
		if err != nil {
			logger.GetLogger().Println("cannot decrypt the recovery phrase during password change, dropping it:", err)
		} else {
			enc, eerr := w2.encrypt(mnemonic)
			ZeroBytes(mnemonic)
			if eerr != nil {
				return fmt.Errorf("failed to encrypt recovery phrase: %v", eerr)
			}
			w2.EncryptedMnemonic = enc
		}
	}

	err := w2.StoreJSON()
	if err != nil {
		logger.GetLogger().Println("Can not store new wallet")
		return err
	}
	loaded, err := LoadJSON(w2.WalletNumber, newPassword, w2.SigName, w2.SigName2)
	if err != nil {
		return err
	}
	w.password = loaded.password
	w.passwordBytes = loaded.passwordBytes
	w.Iv = loaded.Iv
	w.KdfSalt = loaded.KdfSalt
	w.Accounts = loaded.Accounts
	w.EncryptedMnemonic = loaded.EncryptedMnemonic
	ZeroBytes(w.seed) // the old seed (if any) is superseded by loaded.seed below
	w.seed = loaded.seed
	return nil
}

// ChangePasswordInPlace updates the password on the wallet in-place and stores it.
// Unlike ChangePassword, it does not call LoadJSON, so it works for wallets
// loaded from custom directories (e.g. website users).
func (w *Wallet) ChangePasswordInPlace(password, newPassword string) error {
	if w.passwordBytes == nil {
		return fmt.Errorf("you need load wallet first")
	}
	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}
	if !bytes.Equal(w.deriveKey(password), w.passwordBytes) {
		return fmt.Errorf("current password is not valid")
	}

	globalMutex.Lock()
	defer globalMutex.Unlock()

	// Fresh Argon2id salt for the new password; applied to w only after all
	// blobs are re-encrypted (below), so decryption of old blobs still works.
	newSalt := newKdfSalt()
	newPasswordBytes := argon2Key(newPassword, newSalt)

	// Re-encrypt the per-scheme key archive under the new key. w.passwordBytes is
	// still the OLD key throughout this loop (it is swapped only after every blob
	// has been rewritten), which is what makes w.decrypt work here.
	//
	// OB-55: the write back is an assignment, not
	// `copy(w.Accounts[k].EncryptedSecretKey, se)` — see the long note in
	// StoreJSON for why that truncating copy was destroying archives. The
	// undecryptable-entry policy (keep, log, continue) is explained in
	// ChangePassword above; the two must agree, since they are the same operation
	// reached from different callers.
	for k, v := range w.Accounts {
		if err := func() error {
			var plain []byte
			if sk := v.secretKey.GetBytes(); len(sk) > 0 {
				// Unlocked in this session: authoritative, no decrypt needed, and
				// never cleansed here — it is the live key, not a copy.
				plain = sk
			} else {
				ds, err := w.decrypt(v.EncryptedSecretKey)
				if err != nil {
					logger.GetLogger().Printf("WARNING: the archived key for signature scheme %q cannot be decrypted "+
						"with the current (verified correct) password: %v. It is being carried over UNCHANGED, still "+
						"under whatever key it was written with, so nothing is destroyed — but it will NOT open with "+
						"the new password. The wallet's live keys are unaffected and the password change continues. "+
						"If the network ever switches to %q this wallet will refuse to load until it is restored from "+
						"its recovery phrase or a wallet-file backup", k, err, k)
					return nil
				}
				defer func() { // CW-H2: cleanse the ephemeral decrypted key
					if len(ds) > 0 {
						oqs.MemCleanse(ds)
					}
				}()
				plain = ds
			}
			se, err := w.encryptWithKey(newPasswordBytes, plain) // CW-M3: no toggle
			if err != nil {
				logger.GetLogger().Println(err)
				return err
			}
			v.EncryptedSecretKey = se
			w.Accounts[k] = v
			return nil
		}(); err != nil {
			return err
		}
	}

	// Re-encrypt Account1 and Account2
	if len(w.Account1.EncryptedSecretKey) > 0 {
		ds, err := w.decrypt(w.Account1.EncryptedSecretKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt Account1: %v", err)
		}
		defer func() { // CW-H2: cleanse the ephemeral decrypted key
			if len(ds) > 0 {
				oqs.MemCleanse(ds)
			}
		}()
		se, err := w.encryptWithKey(newPasswordBytes, ds) // CW-M3: no toggle
		if err != nil {
			return fmt.Errorf("failed to encrypt Account1: %v", err)
		}
		w.Account1.EncryptedSecretKey = se
	}
	if len(w.Account2.EncryptedSecretKey) > 0 {
		ds, err := w.decrypt(w.Account2.EncryptedSecretKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt Account2: %v", err)
		}
		defer func() { // CW-H2: cleanse the ephemeral decrypted key
			if len(ds) > 0 {
				oqs.MemCleanse(ds)
			}
		}()
		se, err := w.encryptWithKey(newPasswordBytes, ds) // CW-M3: no toggle
		if err != nil {
			return fmt.Errorf("failed to encrypt Account2: %v", err)
		}
		w.Account2.EncryptedSecretKey = se
	}

	// Re-encrypt the recovery phrase under the new key while the old key is
	// still live in w.passwordBytes (decrypt uses w.decrypt, which reads
	// w.passwordBytes). Doing this after the password swap below would try to
	// decrypt an old-key blob with the new key: that fails, and the wallet
	// would otherwise persist a phrase that can never be opened again.
	//
	// If decrypt fails here even under the still-old (just-verified-correct)
	// key, the phrase was already unrecoverable before this call — same
	// degrade-not-abort case as ChangePassword above and as loading (Finding
	// 4). Drop the blob (w.EncryptedMnemonic = nil) instead of aborting the
	// whole password change or carrying forward ciphertext now known to never
	// decrypt.
	if len(w.EncryptedMnemonic) > 0 {
		mnemonic, err := w.decrypt(w.EncryptedMnemonic)
		if err != nil {
			logger.GetLogger().Println("cannot decrypt the recovery phrase during password change, dropping it:", err)
			w.EncryptedMnemonic = nil
		} else {
			enc, eerr := w.encryptWithKey(newPasswordBytes, mnemonic) // CW-M3: no toggle
			ZeroBytes(mnemonic)
			if eerr != nil {
				return fmt.Errorf("failed to encrypt recovery phrase: %v", eerr)
			}
			w.EncryptedMnemonic = enc
		}
	}

	// Now update to new password
	w.password = []byte(newPassword)
	w.passwordBytes = newPasswordBytes
	w.KdfSalt = newSalt

	err := w.StoreJSON()
	if err != nil {
		logger.GetLogger().Println("Can not store new wallet")
		return err
	}
	return nil
}

func (w *Wallet) Sign(data []byte, primary bool) (*common.Signature, error) {
	if len(data) > 0 {
		if primary {
			signature, err := w.Account1.signer.Sign(data)
			if err != nil {
				return nil, err
			}
			signature = append([]byte{0}, signature...)
			sig := &common.Signature{}
			err = sig.Init(signature, w.MainAddress)
			if err != nil {
				return nil, err
			}
			return sig, nil
		} else {
			signature2, err := w.Account2.signer.Sign(data)
			if err != nil {
				return nil, err
			}
			signature2 = append([]byte{1}, signature2...)
			sig := &common.Signature{}
			err = sig.Init(signature2, w.MainAddress)
			if err != nil {
				return nil, err
			}
			return sig, nil
		}
	}
	return nil, fmt.Errorf("input data are empty")
}

func Verify(msg []byte, sig []byte, pubkey []byte, sigName, sigName2 string, isPaused, isPaused2 bool) bool {
	// CW-M1: reject empty signature before indexing; this path is reachable
	// from untrusted network input and must not panic.
	if len(sig) < 1 {
		return false
	}
	if len(msg) < 1 { // CW-M1: empty message would panic the underlying oqs Verify
		return false
	}
	var verifier oqs.Signature
	// CW-H5: always release the liboqs C verifier context. Clean()/OQS_SIG_free
	// tolerate a never-initialized (nil) context, so an unconditional defer is safe.
	defer verifier.Clean()
	var err error
	primary := sig[0] == 0
	sig = sig[1:]
	//logger.GetLogger().Println("Primary:", primary)
	if primary && !isPaused {
		//logger.GetLogger().Println("Primary sign")
		err = verifier.Init(sigName, nil)
		if err != nil {
			logger.GetLogger().Println("verifier:", err)
			return false
		}
		if verifier.Details().LengthPublicKey == len(pubkey) {
			isVerified, err := verifier.Verify(msg, sig, pubkey)

			if err != nil {
				logger.GetLogger().Println(err)
				return false
			}
			if !isVerified {
				logger.GetLogger().Println("msg:", safePrefix(msg), "sig:", safePrefix(sig), "pubkey:", safePrefix(pubkey))
			}
			return isVerified
		}
		logger.GetLogger().Println("verifier.Details().LengthPublicKey:", verifier.Details().LengthPublicKey, "len(pubkey):", len(pubkey))
	}
	if !primary && !isPaused2 {
		//logger.GetLogger().Println("Secondary sign")
		err = verifier.Init(sigName2, nil)
		if err != nil {
			logger.GetLogger().Println("verifier:", err)
			return false
		}
		if verifier.Details().LengthPublicKey == len(pubkey) {
			isVerified, err := verifier.Verify(msg, sig, pubkey)
			if err != nil {
				logger.GetLogger().Println(err)
				return false
			}
			if !isVerified {
				logger.GetLogger().Println("msg:", safePrefix(msg), "sig:", safePrefix(sig), "pubkey:", safePrefix(pubkey))
			}
			return isVerified
		}
		logger.GetLogger().Println("verifier.Details().LengthPublicKey:", verifier.Details().LengthPublicKey, "len(pubkey):", len(pubkey))
	}
	//logger.GetLogger().Println(primary, isPaused, isPaused2)
	return false
}

// safePrefix returns up to the first 5 bytes of b as a string without panicking
// on short input (CW-M1).
func safePrefix(b []byte) string {
	if len(b) > 5 {
		b = b[:5]
	}
	return string(b)
}

func (w *Wallet) GetSecretKey() common.PrivKey {
	if w == nil {
		return common.PrivKey{}
	}
	return w.Account1.secretKey
}

func (w *Wallet) Check() bool {
	if (w != nil) && len(w.passwordBytes) > 0 && (len(w.GetSecretKey().GetBytes()) == w.GetSecretKey().GetLength()) {
		return true
	}
	return false
}

func (w *Wallet) GetSecretKey2() common.PrivKey {
	if w == nil {
		return common.PrivKey{}
	}
	return w.Account2.secretKey
}

func (w *Wallet) Check2() bool {
	if (w != nil) && len(w.passwordBytes) > 0 && (len(w.GetSecretKey2().GetBytes()) == w.GetSecretKey2().GetLength()) {
		return true
	}
	return false
}

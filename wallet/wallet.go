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

	"github.com/wonabru/qwid-node/logger"

	"io"
	"sync"

	"github.com/wonabru/bip39"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/crypto/oqs"
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
	Iv            []byte             `json:"iv"`
	KdfSalt       []byte             `json:"kdf_salt"`
	HomePath      string             `json:"home_path"`
	WalletNumber  uint8              `json:"wallet_number"`
	MainAddress   common.Address     `json:"main_address"`
	SigName       string             `json:"sig_name"`
	SigName2      string             `json:"sig_name_2"`
	Account1      Account            `json:"account_1"`
	Account2      Account            `json:"account_2"`
	Accounts      map[string]Account `json:"accounts"`
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
	w.password = nil
	w.passwordBytes = nil
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
	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		return err
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
func (w *Wallet) encrypt(v []byte) ([]byte, error) {
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
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte{}, err
	}
	// Seal appends the ciphertext (including the auth tag) to nonce, so the
	// returned slice is nonce || ciphertext+tag.
	return gcm.Seal(nonce, nonce, v, nil), nil
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

func (w *Wallet) GetMnemonicWords(primary bool) (string, error) {
	var secret []byte
	var secretLength int
	if primary {
		secret = w.GetSecretKey().GetBytes()
		secretLength = w.GetSecretKey().GetLength()
	} else {
		secret = w.GetSecretKey2().GetBytes()
		secretLength = w.GetSecretKey2().GetLength()
	}
	if secret == nil {
		return "", fmt.Errorf("you need load wallet first")
	}

	if secretLength > 64 {
		return "", fmt.Errorf("secret must be less than 64 bytes")
	}
	if secretLength < 64 {
		logger.GetLogger().Println("not all mnemonic words are important. secret is less than 64 bytes")
		secretTmp := make([]byte, 64)
		copy(secretTmp, secret)
		secret = secretTmp[:]
	}
	mnemonic, _ := bip39.NewMnemonic(secret)

	secretKey, _ := bip39.MnemonicToByteArray(mnemonic)
	if !bytes.Equal(secretKey[:secretLength], secret[:secretLength]) {
		logger.GetLogger().Println("Can not restore secret key from mnemonic")
		return "", fmt.Errorf("can not restore secret key from mnemonic")
	}
	return mnemonic, nil
}

func (w *Wallet) RestoreSecretKeyFromMnemonic(mnemonic string, primary bool) error {
	secretKey, err := bip39.MnemonicToByteArray(mnemonic)
	if err != nil {
		logger.GetLogger().Println("Can not restore secret key")
		return err
	}
	var signer oqs.Signature
	if primary {
		//if len(secretKey) < common.PrivateKeyLength() {
		//	return fmt.Errorf("not enough bytes for primary encryption private key")
		//}
		err = w.Account1.secretKey.Init(secretKey[:], w.Account1.Address, true)
		if err != nil {
			return err
		}

		err = signer.Init(common.SigName(), w.Account1.secretKey.GetBytes())
		if err != nil {
			return err
		}
		(*w).Account1.signer = signer
	} else {
		//if len(secretKey) < common.PrivateKeyLength2() {
		//	return fmt.Errorf("not enough bytes for secondary encryption private key")
		//}
		err = w.Account2.secretKey.Init(secretKey[:], w.Account2.Address, false)
		if err != nil {
			return err
		}
		err = signer.Init(common.SigName2(), w.Account2.secretKey.GetBytes())
		if err != nil {
			return err
		}
		(*w).Account2.signer = signer
	}

	return nil
}

func (w *Wallet) StoreJSON() error {
	if w.GetSecretKey().GetBytes() == nil {
		return fmt.Errorf("you need load wallet first")
	}

	// Create the wallet file path
	walletFile := filepath.Join(w.HomePath, "wallet"+strconv.Itoa(int(w.WalletNumber)))
	logger.GetLogger().Println("walletFile:", walletFile+".json")

	if _, ok := w.Accounts[w.SigName]; !ok {
		logger.GetLogger().Println("not properly structured wallet. Now OK")
		w.Accounts[w.SigName] = w.Account1
		copy(w.Accounts[w.SigName].EncryptedSecretKey[:], w.Account1.EncryptedSecretKey[:])
	}
	if _, ok := w.Accounts[w.SigName2]; !ok {
		logger.GetLogger().Println("not properly structured wallet. Now OK")
		w.Accounts[w.SigName2] = w.Account2
		copy(w.Accounts[w.SigName2].EncryptedSecretKey[:], w.Account2.EncryptedSecretKey[:])
	}

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

	for k, v := range w.Accounts {
		se, err := w.encrypt(v.secretKey.GetBytes())
		if err != nil {
			logger.GetLogger().Println(err)
			return err
		}
		copy(w.Accounts[k].EncryptedSecretKey, se)
	}

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
	if !common.IsPaused() && w.SigName != sigName {
		w.SigName = sigName
		if a, ok := w.Accounts[sigName]; ok {
			w.Account1 = a
			copy(w.Account1.EncryptedSecretKey[:], a.EncryptedSecretKey[:])
		} else {
			acc, err := GenerateNewAccount(*w, sigName)
			if err != nil {
				return nil, err
			}
			w.Account1 = acc
			copy(w.Account1.EncryptedSecretKey[:], acc.EncryptedSecretKey[:])
		}
	}
	if !common.IsPaused2() && w.SigName2 != sigName2 {
		w.SigName2 = sigName2
		if a, ok := w.Accounts[sigName2]; ok {
			w.Account2 = a
			copy(w.Account2.EncryptedSecretKey[:], a.EncryptedSecretKey[:])
		} else {
			acc, err := GenerateNewAccount(*w, sigName2)
			if err != nil {
				return nil, err
			}
			w.Account2 = acc
			copy(w.Account2.EncryptedSecretKey[:], acc.EncryptedSecretKey[:])
		}
	}

	w.SetPassword(password)

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

	w2 := Wallet{
		Iv:           w.Iv,
		HomePath:     w.HomePath,
		WalletNumber: w.WalletNumber,
		MainAddress:  w.MainAddress,
		SigName:      w.SigName,
		SigName2:     w.SigName2,
		Account1:     w.Account1,
		Account2:     w.Account2,
		Accounts:     w.Accounts,
	}
	// Fresh Argon2id salt + key for the new password (KdfSalt left nil so
	// SetPassword generates one).
	w2.SetPassword(newPassword)

	for k, v := range w.Accounts {
		ds, err := w.decrypt(v.EncryptedSecretKey)
		if err != nil {
			logger.GetLogger().Println(err)
			return err
		}
		se, err := w2.encrypt(ds)
		if err != nil {
			logger.GetLogger().Println(err)
			return err
		}
		copy(w2.Accounts[k].EncryptedSecretKey, se)
	}

	// Re-encrypt Account1 and Account2 with the new password
	if len(w2.Account1.EncryptedSecretKey) > 0 {
		ds, err := w.decrypt(w.Account1.EncryptedSecretKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt Account1: %v", err)
		}
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
		se, err := w2.encrypt(ds)
		if err != nil {
			return fmt.Errorf("failed to encrypt Account2: %v", err)
		}
		w2.Account2.EncryptedSecretKey = se
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
	oldPasswordBytes := w.passwordBytes
	newPasswordBytes := argon2Key(newPassword, newSalt)

	// Temporarily keep old password for decryption
	for k, v := range w.Accounts {
		ds, err := w.decrypt(v.EncryptedSecretKey)
		if err != nil {
			logger.GetLogger().Println(err)
			return err
		}
		w.passwordBytes = newPasswordBytes
		se, err := w.encrypt(ds)
		if err != nil {
			w.passwordBytes = oldPasswordBytes
			logger.GetLogger().Println(err)
			return err
		}
		w.passwordBytes = oldPasswordBytes
		copy(w.Accounts[k].EncryptedSecretKey, se)
	}

	// Re-encrypt Account1 and Account2
	if len(w.Account1.EncryptedSecretKey) > 0 {
		ds, err := w.decrypt(w.Account1.EncryptedSecretKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt Account1: %v", err)
		}
		w.passwordBytes = newPasswordBytes
		se, err := w.encrypt(ds)
		if err != nil {
			w.passwordBytes = oldPasswordBytes
			return fmt.Errorf("failed to encrypt Account1: %v", err)
		}
		w.passwordBytes = oldPasswordBytes
		w.Account1.EncryptedSecretKey = se
	}
	if len(w.Account2.EncryptedSecretKey) > 0 {
		ds, err := w.decrypt(w.Account2.EncryptedSecretKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt Account2: %v", err)
		}
		w.passwordBytes = newPasswordBytes
		se, err := w.encrypt(ds)
		if err != nil {
			w.passwordBytes = oldPasswordBytes
			return fmt.Errorf("failed to encrypt Account2: %v", err)
		}
		w.passwordBytes = oldPasswordBytes
		w.Account2.EncryptedSecretKey = se
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

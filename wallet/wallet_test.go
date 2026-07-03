package wallet

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"

	"github.com/stretchr/testify/assert"
)

var mainWallet *Wallet
var err error
var password = "a"

func Init() {
	// Initialize logger for tests
	logger.InitLogger()
	defer logger.CloseLogger()

	// Create an empty wallet first
	wallet := EmptyWallet(255, common.SigName(), common.SigName2())
	wallet.SetPassword(password)
	wallet.Iv = GenerateNewIv()

	// Generate accounts
	acc1, err := GenerateNewAccount(wallet, wallet.SigName)
	if err != nil {
		logger.GetLogger().Fatalf("cannot generate account 1: %v", err)
	}
	wallet.Account1 = acc1
	wallet.MainAddress = acc1.Address

	acc2, err := GenerateNewAccount(wallet, wallet.SigName2)
	if err != nil {
		logger.GetLogger().Fatalf("cannot generate account 2: %v", err)
	}
	wallet.Account2 = acc2

	mainWallet = &wallet
}

func TestGenerateNewWallet(t *testing.T) {
	// Initialize logger for tests
	logger.InitLogger()
	defer logger.CloseLogger()

	password := "testpassword"
	w := EmptyWallet(255, common.SigName(), common.SigName2())
	w.SetPassword(password)
	w.Iv = GenerateNewIv()

	// Generate accounts
	acc1, err := GenerateNewAccount(w, w.SigName)
	assert.NoError(t, err)
	w.Account1 = acc1
	w.MainAddress = acc1.Address

	acc2, err := GenerateNewAccount(w, w.SigName2)
	assert.NoError(t, err)
	w.Account2 = acc2

	assert.NotNil(t, w)
	assert.Equal(t, password, string(w.password))
	assert.NotNil(t, w.passwordBytes)
	assert.NotNil(t, w.Iv)
	assert.NotNil(t, w.Account1.secretKey)
	assert.NotNil(t, w.Account1.PublicKey)
	assert.NotNil(t, w.Account1.Address)
	assert.NotNil(t, w.Account1.signer)
}
func TestStoreAndLoadWallet(t *testing.T) {
	// Initialize logger for tests
	logger.InitLogger()
	defer logger.CloseLogger()

	// Generate a new wallet
	password := "testpassword"
	wallet := EmptyWallet(255, common.SigName(), common.SigName2())
	wallet.SetPassword(password)
	wallet.Iv = GenerateNewIv()

	// Generate accounts
	acc1, err := GenerateNewAccount(wallet, wallet.SigName)
	assert.NoError(t, err)
	wallet.Account1 = acc1
	wallet.MainAddress = acc1.Address

	acc2, err := GenerateNewAccount(wallet, wallet.SigName2)
	assert.NoError(t, err)
	wallet.Account2 = acc2

	// Store the wallet
	err = wallet.StoreJSON()
	assert.NoError(t, err)

	// Load the wallet
	loadedWallet, err := LoadJSON(255, password, common.SigName(), common.SigName2())
	assert.NoError(t, err)

	// Check if the loaded wallet is the same as the original wallet
	assert.Equal(t, wallet.Account1.PublicKey, loadedWallet.Account1.PublicKey)
	assert.Equal(t, wallet.Account1.Address, loadedWallet.Account1.Address)
	assert.Equal(t, wallet.Account1.secretKey, loadedWallet.Account1.secretKey)
}
func TestStoreAndLoadWalletJSON(t *testing.T) {
	// Initialize logger for tests
	logger.InitLogger()
	defer logger.CloseLogger()

	// Generate a new wallet
	password := "xxiii"
	wallet := EmptyWallet(255, common.SigName(), common.SigName2())
	wallet.SetPassword(password)
	wallet.Iv = GenerateNewIv()

	// Generate accounts
	acc1, err := GenerateNewAccount(wallet, wallet.SigName)
	assert.NoError(t, err)
	wallet.Account1 = acc1
	wallet.MainAddress = acc1.Address

	acc2, err := GenerateNewAccount(wallet, wallet.SigName2)
	assert.NoError(t, err)
	wallet.Account2 = acc2

	// Store the wallet
	err = wallet.StoreJSON()
	assert.NoError(t, err)

	// Load the wallet
	loadedWallet, err := LoadJSON(255, password, common.SigName(), common.SigName2())
	assert.NoError(t, err)

	// Check if the loaded wallet is the same as the original wallet
	assert.Equal(t, wallet.Account1.PublicKey, loadedWallet.Account1.PublicKey)
	assert.Equal(t, wallet.Account1.Address, loadedWallet.Account1.Address)
	assert.Equal(t, wallet.Account1.secretKey, loadedWallet.Account1.secretKey)
}
func TestChangePassword(t *testing.T) {
	// Initialize logger for tests
	logger.InitLogger()
	defer logger.CloseLogger()

	// Generate a new wallet
	password := "testpassword"
	newPassword := "newtestpassword"
	wallet := EmptyWallet(255, common.SigName(), common.SigName2())
	wallet.SetPassword(password)
	wallet.Iv = GenerateNewIv()

	// Generate accounts
	acc1, err := GenerateNewAccount(wallet, wallet.SigName)
	assert.NoError(t, err)
	wallet.Account1 = acc1
	wallet.MainAddress = acc1.Address

	acc2, err := GenerateNewAccount(wallet, wallet.SigName2)
	assert.NoError(t, err)
	wallet.Account2 = acc2

	// Store the wallet first
	err = wallet.StoreJSON()
	assert.NoError(t, err)

	// Change the password
	err = wallet.ChangePassword(password, newPassword)
	assert.NoError(t, err)

	// Load the wallet with new password
	loadedWallet, err := LoadJSON(255, newPassword, common.SigName(), common.SigName2())
	assert.NoError(t, err)

	// Check if the loaded wallet is the same as the original wallet
	assert.Equal(t, wallet.Account1.PublicKey, loadedWallet.Account1.PublicKey)
	assert.Equal(t, wallet.Account1.Address, loadedWallet.Account1.Address)
	assert.Equal(t, wallet.Account1.secretKey, loadedWallet.Account1.secretKey)
}
func TestSignAndVerify(t *testing.T) {
	// Initialize logger for tests
	logger.InitLogger()
	defer logger.CloseLogger()

	// Generate a new wallet
	password := "testpassword"
	wallet := EmptyWallet(255, common.SigName(), common.SigName2())
	wallet.SetPassword(password)
	wallet.Iv = GenerateNewIv()

	// Generate accounts
	acc1, err := GenerateNewAccount(wallet, wallet.SigName)
	assert.NoError(t, err)
	wallet.Account1 = acc1
	wallet.MainAddress = acc1.Address

	acc2, err := GenerateNewAccount(wallet, wallet.SigName2)
	assert.NoError(t, err)
	wallet.Account2 = acc2

	// Sign a message using the wallet
	message := []byte("Hello, world!")
	signature, err := wallet.Sign(message, true)
	assert.NoError(t, err)

	// Verify the signature using the wallet's public key
	isVerified := Verify(message, signature.GetBytes(), wallet.Account1.PublicKey.GetBytes(), common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2())
	assert.True(t, isVerified)
}

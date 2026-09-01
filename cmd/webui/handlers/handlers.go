package handlers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/services/transactionServices"
	"github.com/qwid-org/qwid-node/statistics"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/wallet"
)

var MainWallet *wallet.Wallet
var NodeIP string
var DelegatedAccount int

type StatsResponse struct {
	Height              int64   `json:"height"`
	HeightMax           int64   `json:"heightMax"`
	TimeInterval        int64   `json:"timeInterval"`
	Transactions        int     `json:"transactions"`
	TransactionsPending int     `json:"transactionsPending"`
	Tps                 float32 `json:"tps"`
	Syncing             bool    `json:"syncing"`
	Difficulty          int32   `json:"difficulty"`
	PriceOracle         float32 `json:"priceOracle"`
	RandOracle          int64   `json:"randOracle"`
	NodeIP              string  `json:"nodeIP"`
	DelegatedAccount    int     `json:"delegatedAccount"`
	// Sync progress: how many blocks remain to the network height, the import
	// rate over the last two minutes, and the estimated seconds until synced
	// (-1 when no honest estimate exists - fresh window, stall or rewind).
	SyncRemaining    int64   `json:"syncRemaining"`
	SyncBlocksPerSec float64 `json:"syncBlocksPerSec"`
	SyncEtaSeconds   int64   `json:"syncEtaSeconds"`
}

type AccountResponse struct {
	Address         string          `json:"address"`
	Balance         float64         `json:"balance"`
	StakedAmount    float64         `json:"stakedAmount"`
	LockedAmount    float64         `json:"lockedAmount"`
	RewardsAmount   float64         `json:"rewardsAmount"`
	TotalHoldings   float64         `json:"totalHoldings"`
	StakingDetails  []StakingDetail `json:"stakingDetails"`
	EscrowDelay     int64           `json:"escrowDelay"`
	MultiSignNumber uint8           `json:"multiSignNumber"`
	// Which addresses may co-sign. Without this the threshold alone is
	// unactionable: an owner whose transfer sits unapproved cannot tell
	// whether the address that signed is authorised at all.
	MultiSignAddresses []string `json:"multiSignAddresses,omitempty"`
	SentCount          int      `json:"sentCount"`
	ReceivedCount      int      `json:"receivedCount"`
}

type StakingDetail struct {
	DelegatedAddress string  `json:"delegatedAddress"`
	Staked           float64 `json:"staked"`
	Rewards          float64 `json:"rewards"`
}

type WalletInfoResponse struct {
	Loaded    bool   `json:"loaded"`
	Address   string `json:"address"`
	PubKeyHex string `json:"pubKeyHex"`
	SigName   string `json:"sigName"`
	SigName2  string `json:"sigName2"`
}

// walletReady checks if the wallet is loaded and the appropriate account
// (based on encryption pause state) is available.
func walletReady() bool {
	if MainWallet == nil {
		return false
	}
	if !common.IsPaused() {
		return MainWallet.Check()
	}
	return MainWallet.Check2()
}

func GetStats(w http.ResponseWriter, r *http.Request) {
	reply := clientrpc.Call(SignMessage([]byte("STAT")))
	if bytes.Equal(reply, []byte("Timeout")) {
		jsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	sm := statistics.GetStatsManager()
	st := sm.Stats
	err := common.Unmarshal(reply, common.StatDBPrefix, &st)
	if err != nil {
		jsonError(w, "Failed to unmarshal stats", http.StatusInternalServerError)
		return
	}

	remaining := st.HeightMax - st.Height
	if remaining < 0 {
		remaining = 0
	}
	rate, eta := syncEta.observe(time.Now(), st.Height, remaining)

	resp := StatsResponse{
		Height:              st.Height,
		HeightMax:           st.HeightMax,
		TimeInterval:        st.TimeInterval,
		Transactions:        st.Transactions,
		TransactionsPending: st.TransactionsPending,
		Tps:                 st.Tps,
		Syncing:             st.Syncing,
		Difficulty:          st.Difficulty,
		PriceOracle:         st.PriceOracle,
		RandOracle:          st.RandOracle,
		NodeIP:              NodeIP,
		DelegatedAccount:    DelegatedAccount,
		SyncRemaining:       remaining,
		SyncBlocksPerSec:    rate,
		SyncEtaSeconds:      eta,
	}
	jsonResponse(w, resp)
}

func GetWalletInfo(w http.ResponseWriter, r *http.Request) {
	if !walletReady() {
		jsonResponse(w, WalletInfoResponse{Loaded: false})
		return
	}

	resp := WalletInfoResponse{
		Loaded:    true,
		Address:   MainWallet.MainAddress.GetHex(),
		PubKeyHex: common.HexPrefix(MainWallet.Account1.PublicKey.GetHex(), 64),
		SigName:   MainWallet.GetSigName(true),
		SigName2:  MainWallet.GetSigName(false),
	}
	jsonResponse(w, resp)
}

func LoadWallet(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		WalletNumber int    `json:"walletNumber"`
		Password     string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.WalletNumber < 0 || req.WalletNumber > 255 {
		jsonError(w, "Wallet number should be between 0 and 255", http.StatusBadRequest)
		return
	}

	sigName, sigName2, err := SetCurrentEncryptions()
	if err != nil {
		jsonError(w, "Error retrieving encryption", http.StatusInternalServerError)
		return
	}

	loadedWallet, err := wallet.LoadJSON(uint8(req.WalletNumber), req.Password, sigName, sigName2)
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to load wallet: %v", err), http.StatusBadRequest)
		return
	}

	MainWallet = loadedWallet
	TestAndSetEncryption()
	startSession(w) // WH-C3: authenticate this browser session

	warnings := []string{}
	if MainWallet.GetSigName(true) != common.SigName() {
		warnings = append(warnings, "Primary encryption has changed. You may need to update wallet.")
	}
	if MainWallet.GetSigName(false) != common.SigName2() {
		warnings = append(warnings, "Secondary encryption has changed. You may need to update wallet.")
	}

	jsonResponse(w, map[string]interface{}{
		"success":  true,
		"address":  MainWallet.MainAddress.GetHex(),
		"warnings": warnings,
	})
}

func CreateWallet(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		WalletNumber int    `json:"walletNumber"`
		Password     string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.WalletNumber < 0 || req.WalletNumber > 255 {
		jsonError(w, "Wallet number should be between 0 and 255", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 1 {
		jsonError(w, "Password cannot be empty", http.StatusBadRequest)
		return
	}

	sigName, sigName2, err := SetCurrentEncryptions()
	if err != nil {
		jsonError(w, "Error retrieving encryption", http.StatusInternalServerError)
		return
	}

	wl := wallet.EmptyWallet(uint8(req.WalletNumber), sigName, sigName2)
	wl.SetPassword(req.Password)
	wl.Iv = wallet.GenerateNewIv()

	acc, err := wallet.GenerateNewAccount(wl, wl.SigName)
	if err != nil {
		if !common.IsPaused() {
			jsonError(w, fmt.Sprintf("Failed to generate primary account: %v", err), http.StatusInternalServerError)
			return
		}
		logger.GetLogger().Println("Warning: primary account generation failed (paused):", err)
	} else {
		wl.MainAddress = acc.Address
		acc.PublicKey.MainAddress = wl.MainAddress
		wl.Account1 = acc
		copy(wl.Account1.EncryptedSecretKey, acc.EncryptedSecretKey)
	}

	acc, err = wallet.GenerateNewAccount(wl, wl.SigName2)
	if err != nil {
		// Always an error, even though the spare scheme is paused. Paused here
		// means "held in reserve", not "not needed": a wallet created without a
		// working spare key looks fine until the primary scheme is paused, and
		// at that point it cannot sign anything and the key can no longer be
		// registered on-chain either.
		jsonError(w, fmt.Sprintf("Failed to generate secondary (spare) account: %v", err), http.StatusInternalServerError)
		return
	}
	{
		emptyAddr := common.EmptyAddress()
		if bytes.Equal(wl.MainAddress.GetBytes(), emptyAddr.GetBytes()) {
			wl.MainAddress = acc.Address
		}
		acc.PublicKey.MainAddress = wl.MainAddress
		wl.Account2 = acc
		copy(wl.Account2.EncryptedSecretKey, acc.EncryptedSecretKey)
	}

	err = os.MkdirAll(wl.HomePath, 0700) // CW-H3: owner-only; matches StoreJSON's 0700 (MkdirAll won't chmod an existing dir)
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to create wallet directory: %v", err), http.StatusInternalServerError)
		return
	}

	err = wl.StoreJSON()
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to store wallet: %v", err), http.StatusInternalServerError)
		return
	}

	MainWallet = &wl
	TestAndSetEncryption()
	startSession(w) // WH-C3: authenticate this browser session

	// Be explicit that this wallet has NO recovery phrase. The phrase must never
	// cross HTTP (design decision 3), so a wallet created here is generated with
	// random keys and its encrypted file is the ONLY thing that can ever restore
	// it. Saying nothing would leave the user with the impression the README
	// gives for the CLI/GUI flows — that they hold a 24-word backup — which they
	// do not.
	jsonResponse(w, map[string]interface{}{
		"success":  true,
		"address":  wl.MainAddress.GetHex(),
		"mnemonic": false,
		"warning": "This wallet has NO 24-word recovery phrase. The recovery phrase is never sent over HTTP, " +
			"so wallets created in the Web UI cannot have one. Back up the encrypted wallet file " +
			"(" + filepath.Join(wl.HomePath, "wallet"+strconv.Itoa(int(wl.WalletNumber))+".json") + ") " +
			"together with its password — it is the only way to restore this wallet. " +
			"For a wallet backed by a recovery phrase, create it with `go run cmd/generateNewWallet/main.go` or the Qt GUI.",
	})
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}

	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.NewPassword) < 1 {
		jsonError(w, "New password cannot be empty", http.StatusBadRequest)
		return
	}

	if err := MainWallet.ChangePassword(req.CurrentPassword, req.NewPassword); err != nil {
		jsonError(w, fmt.Sprintf("Password change failed: %v", err), http.StatusBadRequest)
		return
	}

	jsonResponse(w, map[string]string{"success": "Password changed"})
}

// GetMnemonic is permanently disabled. The recovery phrase derives every key of
// the wallet, so it must never cross the network: even on localhost it would end
// up in browser history, caches and any proxy in between. Use the CLI
// (cmd/generateNewWallet) or the Qt GUI, which keep it on the machine.
// The route stays registered so clients get this explanation instead of a 404.
func GetMnemonic(w http.ResponseWriter, r *http.Request) {
	jsonError(w, "The recovery phrase is available only locally, in the CLI wallet generator "+
		"or the Qt GUI. It is never served over HTTP.", http.StatusForbidden)
}

func GetAccount(w http.ResponseWriter, r *http.Request) {
	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}

	inb := append([]byte("ACCT"), MainWallet.MainAddress.GetBytes()...)
	re := clientrpc.Call(SignMessage(inb))
	if bytes.Equal(re, []byte("Timeout")) {
		jsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	var acc account.Account
	if err := acc.Unmarshal(re); err != nil {
		jsonError(w, "Failed to unmarshal account", http.StatusInternalServerError)
		return
	}

	conf := acc.GetBalanceConfirmedFloat()
	stake := 0.0
	rewards := 0.0
	locks := 0.0
	stakingDetails := []StakingDetail{}

	// One ACCS call returns the stake across all delegated accounts at once.
	inb = append([]byte("ACCS"), MainWallet.MainAddress.GetBytes()...)
	re = clientrpc.Call(SignMessage(inb))
	if !bytes.Equal(re, []byte("Timeout")) && len(re) >= 4 {
		count := int(common.GetInt32FromByte(re[:4]))
		b := re[4:]
		for j := 0; j < count; j++ {
			blob, rest, err := common.BytesWithLenToBytes(b)
			if err != nil {
				break
			}
			b = rest
			if len(blob) < 8 {
				continue
			}
			var stakeAcc account.StakingAccount
			if err := stakeAcc.Unmarshal(blob[:len(blob)-8]); err != nil {
				continue
			}
			stakedAmount := account.Int64toFloat64(stakeAcc.StakedBalance)
			rewardsAmount := account.Int64toFloat64(stakeAcc.StakingRewards)
			lockedAmount := account.Int64toFloat64(common.GetInt64FromByte(blob[len(blob)-8:]))

			stake += stakedAmount
			rewards += rewardsAmount
			locks += lockedAmount

			if stakeAcc.StakedBalance > 0 || stakeAcc.StakingRewards > 0 {
				a := common.Address{}
				a.Init(stakeAcc.DelegatedAccount[:])
				stakingDetails = append(stakingDetails, StakingDetail{
					DelegatedAddress: a.GetHex(),
					Staked:           stakedAmount,
					Rewards:          rewardsAmount,
				})
			}
		}
	}

	signers := make([]string, 0, len(acc.MultiSignAddresses))
	for _, a := range acc.MultiSignAddresses {
		addr := common.Address{}
		if err := addr.Init(a[:]); err == nil {
			signers = append(signers, addr.GetHex())
		}
	}

	resp := AccountResponse{
		Address:            MainWallet.MainAddress.GetHex(),
		Balance:            conf,
		StakedAmount:       stake,
		LockedAmount:       locks,
		RewardsAmount:      rewards,
		TotalHoldings:      conf + stake + rewards,
		StakingDetails:     stakingDetails,
		EscrowDelay:        acc.TransactionDelay,
		MultiSignNumber:    acc.MultiSignNumber,
		MultiSignAddresses: signers,
		SentCount:          int(acc.SentCount),
		ReceivedCount:      int(acc.ReceivedCount),
	}
	jsonResponse(w, resp)
}

func SendTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}

	var req struct {
		Recipient                  string  `json:"recipient"`
		Amount                     float64 `json:"amount"`
		LockedAmount               float64 `json:"lockedAmount"`
		ReleasePerBlock            float64 `json:"releasePerBlock"`
		DelegatedAccountForLocking string  `json:"delegatedAccountForLocking"`
		MultiSigTxHash             string  `json:"multiSigTxHash"`
		SmartContractData          string  `json:"smartContractData"`
		IncludePubKey              bool    `json:"includePubKey"`
		UsePrimaryEncryption       bool    `json:"usePrimaryEncryption"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Parse recipient address
	ar := common.Address{}
	if len(req.Recipient) < 20 {
		i, err := strconv.Atoi(req.Recipient)
		if err != nil || i > 255 {
			jsonError(w, "Invalid delegated account number", http.StatusBadRequest)
			return
		}
		ar = common.GetDelegatedAccountAddress(int16(i))
	} else {
		bar, err := hex.DecodeString(req.Recipient)
		if err != nil {
			jsonError(w, "Invalid recipient address hex", http.StatusBadRequest)
			return
		}
		if err := ar.Init(bar); err != nil {
			jsonError(w, "Invalid recipient address", http.StatusBadRequest)
			return
		}
	}

	// Reject regular transfers to delegated accounts — use staking operations instead
	if n, err := account.IntDelegatedAccountFromAddress(ar); err == nil && n > 0 {
		isStakingOp := req.LockedAmount > 0 || req.Amount < 0 || len(req.SmartContractData) > 0 || req.MultiSigTxHash != ""
		if !isStakingOp {
			jsonError(w, "Cannot send regular transfer to delegated account. Use staking operations instead.", http.StatusBadRequest)
			return
		}
	}

	// Validate and convert amounts
	if req.Amount < 0 {
		jsonError(w, "Amount cannot be negative", http.StatusBadRequest)
		return
	}
	am := common.CoinToBaseUnits(req.Amount)

	if req.LockedAmount < 0 {
		jsonError(w, "Locked amount cannot be negative", http.StatusBadRequest)
		return
	}
	if req.LockedAmount > req.Amount {
		jsonError(w, "Locked amount cannot be larger than amount", http.StatusBadRequest)
		return
	}
	lam := common.CoinToBaseUnits(req.LockedAmount)

	if req.ReleasePerBlock < 0 {
		jsonError(w, "Release per block cannot be negative", http.StatusBadRequest)
		return
	}
	if req.ReleasePerBlock > req.LockedAmount {
		jsonError(w, "Release per block cannot be larger than locked amount", http.StatusBadRequest)
		return
	}
	rlam := common.CoinToBaseUnits(req.ReleasePerBlock)

	// Parse delegated account for locking
	lar := common.Address{}
	if req.DelegatedAccountForLocking == "" {
		req.DelegatedAccountForLocking = "1"
	}
	if len(req.DelegatedAccountForLocking) < 20 {
		i, err := strconv.Atoi(req.DelegatedAccountForLocking)
		if err != nil || i > 255 {
			jsonError(w, "Invalid delegated account for locking", http.StatusBadRequest)
			return
		}
		lar = common.GetDelegatedAccountAddress(int16(i))
	} else {
		bar, err := hex.DecodeString(req.DelegatedAccountForLocking)
		if err != nil {
			jsonError(w, "Invalid delegated account for locking hex", http.StatusBadRequest)
			return
		}
		if err := lar.Init(bar); err != nil {
			jsonError(w, "Invalid delegated account for locking", http.StatusBadRequest)
			return
		}
	}

	// Parse multi-sig hash if provided
	hashms := common.Hash{}
	if req.MultiSigTxHash != "" {
		har, err := hex.DecodeString(req.MultiSigTxHash)
		if err != nil {
			jsonError(w, "Invalid multi-sig hash hex", http.StatusBadRequest)
			return
		}
		if len(har) != common.HashLength {
			jsonError(w, "Hash should be 32 bytes (64 hex characters)", http.StatusBadRequest)
			return
		}
		hashms.Set(har)
	}

	// Parse smart contract data if provided
	scData := []byte{}
	if len(req.SmartContractData) > 0 {
		var err error
		scData, err = hex.DecodeString(req.SmartContractData)
		if err != nil {
			scData = []byte{}
		}
	}

	// Public key inclusion
	// Two separate decisions, previously conflated into one flag.
	//
	// WHICH KEY TO REGISTER is the operator's choice: usePrimaryEncryption picks
	// the public key that travels in the transaction.
	//
	// WHICH KEY SIGNS is not a choice at all — it must be the scheme that is
	// live right now. The case that matters is registering the primary key
	// straight after a scheme replacement: that key arrives PAUSED and cannot
	// sign anything, so the spare (live precisely while the primary is paused)
	// has to sign for it. Leaving this to a checkbox meant the operator sent a
	// transaction signed with a paused scheme and got back nothing more useful
	// than "transaction fail to verify".
	SetCurrentEncryptions()
	signPrimary := !common.IsPaused()

	pk := common.PubKey{}
	if req.IncludePubKey {
		// "Register Paused public key" means the key of whichever scheme is
		// currently PAUSED — not Account1. Which slot that is follows from the
		// pause state: while the primary is live the spare is the paused one,
		// and after the primary is paused it becomes the paused one itself.
		//
		// Tying this to Account1 registered the live scheme's key, which is
		// already registered and never the one that needs it. The key that
		// needs registering is always the paused one: a scheme arrives paused
		// and cannot sign for itself, which is why the live scheme signs for it.
		registerPrimary := !signPrimary
		if !req.UsePrimaryEncryption {
			// Unchecked: register the live scheme's key instead.
			registerPrimary = signPrimary
		}
		if registerPrimary {
			pk = MainWallet.Account1.PublicKey
		} else {
			pk = MainWallet.Account2.PublicKey
		}

		// Bootstrap overrides that choice, because for an identity with NOTHING
		// registered on-chain the choice does not exist.
		//
		// The reasoning above concerns a scheme REPLACEMENT: the incoming key
		// arrives paused and the already-registered live key vouches for it. An
		// identity with no registered key has nothing to vouch for anything, so
		// consensus accepts exactly one key from it — the one that DERIVES its
		// address. The address is a hash of that key, so holding it is the only
		// self-evident proof a first key can offer.
		//
		// Without this, a new node could not register through this form at all:
		// with the box ticked it offered the spare, which cannot open an
		// account, and the transaction died at the far end reporting only that
		// the sender had no registered key.
		if !identityHasRegisteredKey() {
			switch {
			case bytes.Equal(MainWallet.Account1.Address.GetBytes(), MainWallet.MainAddress.GetBytes()):
				pk = MainWallet.Account1.PublicKey
				registerPrimary = true
			case bytes.Equal(MainWallet.Account2.Address.GetBytes(), MainWallet.MainAddress.GetBytes()):
				pk = MainWallet.Account2.PublicKey
				registerPrimary = false
			default:
				jsonError(w, "Nothing is registered on-chain for this wallet yet, and neither of its keys derives "+
					"its own address ("+MainWallet.MainAddress.GetHex()+"). An identity's first key must be the one "+
					"its address comes from, so no key here can open this account — restore the wallet that owns it.",
					http.StatusBadRequest)
				return
			}
			logger.GetLogger().Printf("nothing registered for %s yet: sending the key that derives it, "+
				"the only key consensus accepts as an identity's first",
				MainWallet.MainAddress.GetHex())
		}
		logger.GetLogger().Printf("including pubkey for registration: %s slot (%s), %d bytes",
			map[bool]string{true: "primary", false: "secondary"}[registerPrimary],
			map[bool]string{true: common.SigName(), false: common.SigName2()}[registerPrimary],
			len(pk.GetBytes()))
	}

	// Build transaction
	txd := transactionsDefinition.TxData{
		Recipient:                  ar,
		Amount:                     am,
		OptData:                    scData,
		Pubkey:                     pk,
		LockedAmount:               lam,
		ReleasePerBlock:            rlam,
		DelegatedAccountForLocking: lar,
	}

	par := transactionsDefinition.TxParam{
		ChainID:     int16(23),
		Sender:      MainWallet.MainAddress,
		SendingTime: common.GetCurrentTimeStampInSecond(),
		Nonce:       common.RandomNonce(),
	}
	if req.MultiSigTxHash != "" {
		par.MultiSignTx = hashms
	}

	tx := transactionsDefinition.Transaction{
		TxData:    txd,
		TxParam:   par,
		Hash:      common.Hash{},
		Signature: common.Signature{},
		Height:    0,
		GasPrice:  int64(rand.Intn(0x0000000f)) + 1,
		GasUsage:  0,
	}

	// Get current height from stats
	reply := clientrpc.Call(SignMessage([]byte("STAT")))
	sm := statistics.GetStatsManager()
	st := sm.Stats
	if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
		jsonError(w, "Failed to get network stats", http.StatusInternalServerError)
		return
	}

	tx.GasUsage = tx.GasUsageEstimate()
	tx.Height = st.Height

	if err := tx.CalcHashAndSet(); err != nil {
		jsonError(w, fmt.Sprintf("Failed to calculate hash: %v", err), http.StatusInternalServerError)
		return
	}

	if err := tx.Sign(MainWallet, signPrimary); err != nil {
		jsonError(w, fmt.Sprintf("Failed to sign transaction: %v", err), http.StatusInternalServerError)
		return
	}

	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to generate message: %v", err), http.StatusInternalServerError)
		return
	}

	tmm := msg.GetBytes()
	clientrpc.Call(SignMessage(append([]byte("TRAN"), tmm...)))

	jsonResponse(w, map[string]string{
		"success": "true",
		"txHash":  tx.Hash.GetHex(),
		"message": "Transaction sent successfully",
	})
}

func CancelTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}

	var req struct {
		TxHash string `json:"txHash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	tmm, err := hex.DecodeString(req.TxHash)
	if err != nil || len(tmm) != common.HashLength {
		jsonError(w, "Invalid transaction hash", http.StatusBadRequest)
		return
	}

	// Name the account the cancellation is for. Without it the node checks
	// ownership against the wallet it mines with, so any other wallet was told
	// "you are not the owner" about its own transaction.
	cancel := append([]byte("CNCL"), MainWallet.MainAddress.GetBytes()...)
	reply := clientrpc.Call(SignMessage(append(cancel, tmm...)))
	if string(reply) != "escrow cancellation transaction required" {
		jsonResponse(w, map[string]string{"message": string(reply)})
		return
	}

	var target common.Hash
	target.Set(tmm)
	tx := transactionsDefinition.Transaction{
		TxData: transactionsDefinition.TxData{
			Recipient: MainWallet.MainAddress,
			Amount:    0,
			OptData:   transactionsDefinition.CancellationOptData(target),
		},
		TxParam: transactionsDefinition.TxParam{
			ChainID:     int16(23),
			Sender:      MainWallet.MainAddress,
			SendingTime: common.GetCurrentTimeStampInSecond(),
			Nonce:       common.RandomNonce(),
		},
		GasPrice: int64(rand.Intn(0x0000000f)) + 1,
	}
	statsReply := clientrpc.Call(SignMessage([]byte("STAT")))
	stats := statistics.GetStatsManager().Stats
	if err := common.Unmarshal(statsReply, common.StatDBPrefix, &stats); err != nil {
		jsonError(w, "Failed to get network stats", http.StatusInternalServerError)
		return
	}
	tx.Height = stats.Height
	tx.GasUsage = tx.GasUsageEstimate()
	if err := tx.CalcHashAndSet(); err != nil {
		jsonError(w, fmt.Sprintf("Failed to calculate cancellation hash: %v", err), http.StatusInternalServerError)
		return
	}
	// Refresh the scheme state from the node before choosing which key signs.
	// This process caches it, and a signature-scheme pause or replacement happens
	// on the chain, not here: without the refresh the UI keeps signing with a
	// scheme the node has since paused, and every such transaction is rejected.
	SetCurrentEncryptions()
	primary := !common.IsPaused()
	if err := tx.Sign(MainWallet, primary); err != nil {
		jsonError(w, fmt.Sprintf("Failed to sign cancellation: %v", err), http.StatusInternalServerError)
		return
	}
	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to generate cancellation message: %v", err), http.StatusInternalServerError)
		return
	}
	clientrpc.Call(SignMessage(append([]byte("TRAN"), msg.GetBytes()...)))

	jsonResponse(w, map[string]string{
		"success": "true",
		"txHash":  tx.Hash.GetHex(),
		"message": "Escrow cancellation transaction sent",
	})
}

func Stake(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]string{"status": "use /api/staking/execute"})
}

func Unstake(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]string{"status": "use /api/staking/execute"})
}

func ClaimRewards(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]string{"status": "use /api/staking/execute"})
}

func ExecuteStaking(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}

	var req struct {
		Action               string  `json:"action"` // stake, unstake, withdraw
		DelegatedAccount     string  `json:"delegatedAccount"`
		Amount               float64 `json:"amount"`
		IntendOperator       bool    `json:"intendOperator"`
		IncludePubKey        bool    `json:"includePubKey"`
		UsePrimaryEncryption bool    `json:"usePrimaryEncryption"`
		TargetOperator       string  `json:"targetOperator"` // Address to stake FOR (optional)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Parse delegated account
	ar := common.Address{}
	di, err := strconv.ParseInt(req.DelegatedAccount, 10, 16)
	if err != nil {
		bar, err := hex.DecodeString(req.DelegatedAccount)
		if err != nil {
			jsonError(w, "Invalid delegated account", http.StatusBadRequest)
			return
		}
		if err := ar.Init(bar); err != nil {
			jsonError(w, "Invalid delegated account address", http.StatusBadRequest)
			return
		}
	} else {
		if req.Action == "withdraw" {
			ar = common.GetDelegatedAccountAddress(int16(di + 256))
		} else {
			ar = common.GetDelegatedAccountAddress(int16(di))
		}
	}

	if _, err := account.IntDelegatedAccountFromAddress(ar); err != nil {
		jsonError(w, fmt.Sprintf("Invalid delegated account: %s", ar.GetHex()), http.StatusBadRequest)
		return
	}

	// Validate and convert amount
	if req.Amount <= 0 {
		jsonError(w, "Amount must be greater than 0", http.StatusBadRequest)
		return
	}

	am := common.CoinToBaseUnits(req.Amount)

	// Check minimum staking
	if req.Action == "stake" && am < common.MinStakingUser {
		jsonError(w, fmt.Sprintf("Minimum staking amount is %f", float64(common.MinStakingUser)/1e8), http.StatusBadRequest)
		return
	}

	// Negate amount for unstake/withdraw
	if req.Action == "unstake" || req.Action == "withdraw" {
		am *= -1
	}

	// Operator flag
	optData := []byte{}
	if req.IntendOperator {
		optData = []byte{1}
	}

	// Public key
	// Two separate decisions, previously conflated into one flag.
	//
	// WHICH KEY TO REGISTER is the operator's choice: usePrimaryEncryption picks
	// the public key that travels in the transaction.
	//
	// WHICH KEY SIGNS is not a choice at all — it must be the scheme that is
	// live right now. The case that matters is registering the primary key
	// straight after a scheme replacement: that key arrives PAUSED and cannot
	// sign anything, so the spare (live precisely while the primary is paused)
	// has to sign for it. Leaving this to a checkbox meant the operator sent a
	// transaction signed with a paused scheme and got back nothing more useful
	// than "transaction fail to verify".
	SetCurrentEncryptions()
	signPrimary := !common.IsPaused()

	pk := common.PubKey{}
	if req.IncludePubKey {
		// Only the Send form registers a key for a paused scheme; everywhere
		// else the live scheme is the one in use, so attach its key.
		registerPrimary := signPrimary
		if registerPrimary {
			pk = MainWallet.Account1.PublicKey
		} else {
			pk = MainWallet.Account2.PublicKey
		}
		logger.GetLogger().Printf("including pubkey for registration: %s slot (%s), %d bytes",
			map[bool]string{true: "primary", false: "secondary"}[registerPrimary],
			map[bool]string{true: common.SigName(), false: common.SigName2()}[registerPrimary],
			len(pk.GetBytes()))
	}

	// Build transaction
	var recipient common.Address
	var lockedAmount int64 = 0
	var releasePerBlock int64 = 0
	var delegatedAccountForLocking common.Address

	if req.TargetOperator != "" && req.Action == "stake" {
		// Staking FOR another node - use locked staking path
		targetBytes, err := hex.DecodeString(req.TargetOperator)
		if err != nil || len(targetBytes) != common.AddressLength {
			jsonError(w, "Invalid target operator address", http.StatusBadRequest)
			return
		}
		recipient = common.Address{}
		if err := recipient.Init(append([]byte{1}, targetBytes...)); err != nil {
			jsonError(w, "Failed to init target operator address", http.StatusBadRequest)
			return
		}
		// Use locked staking with immediate release (all released in 1 block)
		lockedAmount = am
		releasePerBlock = am
		delegatedAccountForLocking = ar // The delegated account
	} else {
		recipient = ar
		delegatedAccountForLocking = common.GetDelegatedAccountAddress(1)
	}

	txd := transactionsDefinition.TxData{
		Recipient:                  recipient,
		Amount:                     am,
		OptData:                    optData,
		Pubkey:                     pk,
		LockedAmount:               lockedAmount,
		ReleasePerBlock:            releasePerBlock,
		DelegatedAccountForLocking: delegatedAccountForLocking,
	}

	par := transactionsDefinition.TxParam{
		ChainID:     int16(23),
		Sender:      MainWallet.MainAddress,
		SendingTime: common.GetCurrentTimeStampInSecond(),
		Nonce:       common.RandomNonce(),
	}

	tx := transactionsDefinition.Transaction{
		TxData:    txd,
		TxParam:   par,
		Hash:      common.Hash{},
		Signature: common.Signature{},
		Height:    0,
		GasPrice:  int64(rand.Intn(0x0000000f)) + 1,
		GasUsage:  0,
	}

	// Get current height
	reply := clientrpc.Call(SignMessage([]byte("STAT")))
	sm := statistics.GetStatsManager()
	st := sm.Stats
	if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
		jsonError(w, "Failed to get network stats", http.StatusInternalServerError)
		return
	}

	tx.GasUsage = tx.GasUsageEstimate()
	tx.Height = st.Height

	if err := tx.CalcHashAndSet(); err != nil {
		jsonError(w, fmt.Sprintf("Failed to calculate hash: %v", err), http.StatusInternalServerError)
		return
	}

	if err := tx.Sign(MainWallet, signPrimary); err != nil {
		jsonError(w, fmt.Sprintf("Failed to sign transaction: %v", err), http.StatusInternalServerError)
		return
	}

	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to generate message: %v", err), http.StatusInternalServerError)
		return
	}

	tmm := msg.GetBytes()
	clientrpc.Call(SignMessage(append([]byte("TRAN"), tmm...)))

	jsonResponse(w, map[string]string{
		"success": "true",
		"txHash":  tx.Hash.GetHex(),
		"message": "Staking transaction sent successfully",
	})
}

func GetPendingTransactions(w http.ResponseWriter, r *http.Request) {
	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}
	// Ask for THIS wallet's pending transactions. The pools hold the whole
	// network's traffic, so an unnamed request answered with a list the wallet
	// could not attribute to itself.
	reply := clientrpc.Call(SignMessage(append([]byte("PEND"), MainWallet.MainAddress.GetBytes()...)))
	if bytes.Equal(reply, []byte("Timeout")) {
		jsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	// Parse the response - it contains transaction data
	transactions := []map[string]interface{}{}

	if len(reply) > 0 {
		// Try to parse as JSON first
		var txList []map[string]interface{}
		if err := json.Unmarshal(reply, &txList); err == nil {
			transactions = txList
		} else {
			// Return raw data if not JSON
			jsonResponse(w, map[string]interface{}{
				"raw":   hex.EncodeToString(reply),
				"count": 0,
			})
			return
		}
	}

	jsonResponse(w, map[string]interface{}{
		"transactions": transactions,
		"count":        len(transactions),
	})
}

func GetHistory(w http.ResponseWriter, r *http.Request) {
	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}

	// Get account to fetch transaction hashes
	inb := append([]byte("ACCT"), MainWallet.MainAddress.GetBytes()...)
	re := clientrpc.Call(SignMessage(inb))
	if bytes.Equal(re, []byte("Timeout")) {
		jsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	var acc account.Account
	if err := acc.Unmarshal(re); err != nil {
		jsonError(w, "Failed to unmarshal account", http.StatusInternalServerError)
		return
	}

	transactions := []map[string]interface{}{}

	// Fetch sent transactions (limit to last 50)
	sentHashes := acc.TransactionsSender
	if len(sentHashes) > 50 {
		sentHashes = sentHashes[len(sentHashes)-50:]
	}
	for i := len(sentHashes) - 1; i >= 0; i-- {
		h := sentHashes[i]
		reply := clientrpc.Call(SignMessage(append([]byte("DETS"), h.GetBytes()...)))
		if len(reply) > 3 && string(reply[:2]) == "TX" {
			locLen := int(reply[2])
			if len(reply) > 3+locLen {
				tx := transactionsDefinition.Transaction{}
				tx, _, err := tx.GetFromBytes(reply[3+locLen:])
				if err == nil {
					transactions = append(transactions, map[string]interface{}{
						"type":      "sent",
						"hash":      tx.Hash.GetHex(),
						"recipient": tx.TxData.Recipient.GetHex(),
						"amount":    account.Int64toFloat64(tx.TxData.Amount),
						"height":    tx.Height,
						"time":      tx.TxParam.SendingTime,
						// DETS already reports where the transaction lives; the
						// history discarded it and listed everything alike, so a
						// transfer still sitting in escrow looked settled.
						"location": string(reply[3 : 3+locLen]),
					})
				}
			}
		}
	}

	// Fetch received transactions (limit to last 50)
	recvHashes := acc.TransactionsRecipient
	if len(recvHashes) > 50 {
		recvHashes = recvHashes[len(recvHashes)-50:]
	}
	for i := len(recvHashes) - 1; i >= 0; i-- {
		h := recvHashes[i]
		reply := clientrpc.Call(SignMessage(append([]byte("DETS"), h.GetBytes()...)))
		if len(reply) > 3 && string(reply[:2]) == "TX" {
			locLen := int(reply[2])
			if len(reply) > 3+locLen {
				tx := transactionsDefinition.Transaction{}
				tx, _, err := tx.GetFromBytes(reply[3+locLen:])
				if err == nil {
					transactions = append(transactions, map[string]interface{}{
						"type":     "received",
						"hash":     tx.Hash.GetHex(),
						"sender":   tx.TxParam.Sender.GetHex(),
						"amount":   account.Int64toFloat64(tx.TxData.Amount),
						"height":   tx.Height,
						"time":     tx.TxParam.SendingTime,
						"location": string(reply[3 : 3+locLen]),
					})
				}
			}
		}
	}

	jsonResponse(w, map[string]interface{}{
		"transactions": transactions,
		"address":      MainWallet.MainAddress.GetHex(),
	})
}

func GetDetails(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		jsonError(w, "Hash parameter required", http.StatusBadRequest)
		return
	}

	var b []byte
	var err error
	if len(hash) < 16 {
		height, err := strconv.Atoi(hash)
		if err != nil {
			jsonError(w, "Invalid height format", http.StatusBadRequest)
			return
		}
		b = common.GetByteInt64(int64(height))
	} else {
		b, err = hex.DecodeString(hash)
		if err != nil {
			jsonError(w, "Invalid hash format", http.StatusBadRequest)
			return
		}
	}

	reply := clientrpc.Call(SignMessage(append([]byte("DETS"), b...)))
	if len(reply) <= 2 {
		jsonError(w, "Not found", http.StatusNotFound)
		return
	}

	switch string(reply[:2]) {
	case "TX":
		// Format: "TX" + 1 byte location length + location string + tx bytes
		if len(reply) < 3 {
			jsonError(w, "Transaction not found", http.StatusNotFound)
			return
		}
		locLen := int(reply[2])
		if len(reply) < 3+locLen {
			jsonError(w, "Invalid response format", http.StatusInternalServerError)
			return
		}
		location := string(reply[3 : 3+locLen])
		tx := transactionsDefinition.Transaction{}
		tx, _, err := tx.GetFromBytes(reply[3+locLen:])
		if err != nil {
			jsonError(w, "Failed to parse transaction", http.StatusInternalServerError)
			return
		}
		jsonResponse(w, map[string]interface{}{
			"type":     "transaction",
			"data":     tx.GetString(),
			"location": location,
		})
	case "AC":
		var acc account.Account
		if err := acc.Unmarshal(reply[2:]); err != nil {
			jsonError(w, "Failed to parse account", http.StatusInternalServerError)
			return
		}

		// Fetch transaction history for this account
		transactions := []map[string]interface{}{}

		// Fetch sent transactions (limit to last 20)
		sentHashes := acc.TransactionsSender
		if len(sentHashes) > 20 {
			sentHashes = sentHashes[len(sentHashes)-20:]
		}
		for i := len(sentHashes) - 1; i >= 0; i-- {
			h := sentHashes[i]
			txReply := clientrpc.Call(SignMessage(append([]byte("DETS"), h.GetBytes()...)))
			if len(txReply) > 3 && string(txReply[:2]) == "TX" {
				locLen := int(txReply[2])
				if len(txReply) > 3+locLen {
					tx := transactionsDefinition.Transaction{}
					tx, _, err := tx.GetFromBytes(txReply[3+locLen:])
					if err == nil {
						transactions = append(transactions, map[string]interface{}{
							"type":      "sent",
							"hash":      tx.Hash.GetHex(),
							"recipient": tx.TxData.Recipient.GetHex(),
							"amount":    account.Int64toFloat64(tx.TxData.Amount),
							"height":    tx.Height,
						})
					}
				}
			}
		}

		// Fetch received transactions (limit to last 20)
		recvHashes := acc.TransactionsRecipient
		if len(recvHashes) > 20 {
			recvHashes = recvHashes[len(recvHashes)-20:]
		}
		for i := len(recvHashes) - 1; i >= 0; i-- {
			h := recvHashes[i]
			txReply := clientrpc.Call(SignMessage(append([]byte("DETS"), h.GetBytes()...)))
			if len(txReply) > 3 && string(txReply[:2]) == "TX" {
				locLen := int(txReply[2])
				if len(txReply) > 3+locLen {
					tx := transactionsDefinition.Transaction{}
					tx, _, err := tx.GetFromBytes(txReply[3+locLen:])
					if err == nil {
						transactions = append(transactions, map[string]interface{}{
							"type":   "received",
							"hash":   tx.Hash.GetHex(),
							"sender": tx.TxParam.Sender.GetHex(),
							"amount": account.Int64toFloat64(tx.TxData.Amount),
							"height": tx.Height,
						})
					}
				}
			}
		}

		// Get address hex
		addr := common.Address{}
		addr.Init(acc.Address[:])

		jsonResponse(w, map[string]interface{}{
			"type":             "account",
			"address":          addr.GetHex(),
			"balance":          acc.GetBalanceConfirmedFloat(),
			"transactionDelay": acc.TransactionDelay,
			"multiSignNumber":  acc.MultiSignNumber,
			"sentCount":        acc.SentCount,
			"receivedCount":    acc.ReceivedCount,
			"transactions":     transactions,
		})
	case "BL":
		bb := blocks.Block{}
		bb, err = bb.GetFromBytes(reply[2:])
		if err != nil {
			jsonError(w, "Failed to parse block", http.StatusInternalServerError)
			return
		}
		jsonResponse(w, map[string]interface{}{
			"type": "block",
			"data": bb.GetString(),
		})
	default:
		jsonResponse(w, map[string]interface{}{
			"type": "unknown",
			"data": string(reply),
		})
	}
}

func GetTokens(w http.ResponseWriter, r *http.Request) {
	reply := clientrpc.Call(SignMessage([]byte("LTKN")))
	if bytes.Equal(reply, []byte("Timeout")) {
		jsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	var tokens map[string]interface{}
	if err := json.Unmarshal(reply, &tokens); err != nil {
		jsonResponse(w, map[string]interface{}{"tokens": map[string]interface{}{}})
		return
	}
	jsonResponse(w, map[string]interface{}{"tokens": tokens})
}

func GetPools(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{"pools": []interface{}{}})
}

func Trade(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]string{"status": "not implemented"})
}

// identityHasRegisteredKey reports whether the active wallet's identity already
// has any key recorded on-chain. It decides between the two registration
// regimes: bootstrap, where only the address-deriving key is admissible, and
// every later registration, which an existing key authorises.
//
// A node that cannot be asked is treated as "already registered", so a failed
// query cannot silently rewrite which key the operator is sending; the
// transaction is then judged by consensus, as it would have been anyway.
func identityHasRegisteredKey() bool {
	reply := clientrpc.Call(SignMessage(append([]byte("PUBA"), MainWallet.MainAddress.GetBytes()...)))
	if bytes.Equal(reply, []byte("Timeout")) {
		logger.GetLogger().Println("could not ask the node which keys are registered; assuming the identity is known")
		return true
	}
	var resp struct {
		HasPrimary   bool `json:"hasPrimary"`
		HasSecondary bool `json:"hasSecondary"`
	}
	if err := json.Unmarshal(reply, &resp); err != nil {
		logger.GetLogger().Println("could not read the registered-key reply; assuming the identity is known:", err)
		return true
	}
	return resp.HasPrimary || resp.HasSecondary
}

func GetPubKeyInfo(w http.ResponseWriter, r *http.Request) {
	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}

	reply := clientrpc.Call(SignMessage(append([]byte("PUBA"), MainWallet.MainAddress.GetBytes()...)))
	if bytes.Equal(reply, []byte("Timeout")) {
		jsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(reply, &resp); err != nil {
		jsonError(w, "Failed to parse pubkey info", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, resp)
}

func GetEncryptionStatus(w http.ResponseWriter, r *http.Request) {
	// Refresh encryption config from node
	SetCurrentEncryptions()

	jsonResponse(w, map[string]interface{}{
		"primaryName":            common.SigName(),
		"primaryPaused":          common.IsPaused(),
		"primaryPubKeyLength":    common.PubKeyLength(false),
		"primarySignatureLength": common.SignatureLength(false),

		"secondaryName":            common.SigName2(),
		"secondaryPaused":          common.IsPaused2(),
		"secondaryPubKeyLength":    common.PubKeyLength2(false),
		"secondarySignatureLength": common.SignatureLength2(false),

		"votingWindow": common.VotingHeightDistance,
	})
}

func Vote(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}

	var req struct {
		Action         string `json:"action"`         // pausePrimary, unpausePrimary, replacePrimary, replaceSecondary
		EncryptionName string `json:"encryptionName"` // Name of encryption (optional, uses current if empty)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var enb []byte

	switch req.Action {
	case "pausePrimary", "unpausePrimary", "replacePrimary":
		encName := req.EncryptionName
		if encName == "" {
			encName = common.SigName()
		}
		config, err := oqs.GenerateEncConfig(encName)
		if err != nil {
			jsonError(w, fmt.Sprintf("Invalid encryption name: %v", err), http.StatusBadRequest)
			return
		}
		isPaused := req.Action == "pausePrimary" || req.Action == "replacePrimary"
		enb1, err := oqs.GenerateBytesFromParams(config.SigName, config.PubKeyLength, config.PrivateKeyLength, config.SignatureLength, isPaused)
		if err != nil {
			jsonError(w, fmt.Sprintf("Failed to generate encryption params: %v", err), http.StatusInternalServerError)
			return
		}
		enb = common.BytesToLenAndBytes(enb1)
		enb = append(enb, common.BytesToLenAndBytes([]byte{})...)

	case "pauseSecondary", "unpauseSecondary":
		// The spare's liveness is derived from the primary's (common.IsPaused2),
		// so voting it on or off separately cannot express anything: exactly one
		// scheme is usable at a time, and which one follows from whether the
		// primary is paused. Accepting these would let an operator publish a
		// config the invariant forbids.
		jsonError(w, "the secondary scheme is the spare: it is paused whenever the primary is live and usable "+
			"whenever the primary is paused, so it cannot be paused or unpaused on its own. "+
			"Use pausePrimary/unpausePrimary, or replaceSecondary to change which algorithm the spare is.",
			http.StatusBadRequest)
		return

	case "replaceSecondary":
		encName := req.EncryptionName
		if encName == "" {
			encName = common.SigName2()
		}
		config, err := oqs.GenerateEncConfig(encName)
		if err != nil {
			jsonError(w, fmt.Sprintf("Invalid encryption name: %v", err), http.StatusBadRequest)
			return
		}
		// A spare is by definition not live, and its state is derived anyway.
		isPaused := true
		enb2, err := oqs.GenerateBytesFromParams(config.SigName, config.PubKeyLength, config.PrivateKeyLength, config.SignatureLength, isPaused)
		if err != nil {
			jsonError(w, fmt.Sprintf("Failed to generate encryption params: %v", err), http.StatusInternalServerError)
			return
		}
		enb = common.BytesToLenAndBytes([]byte{})
		enb = append(enb, common.BytesToLenAndBytes(enb2)...)

	default:
		jsonError(w, "Invalid action. Use: pausePrimary, unpausePrimary, replacePrimary, replaceSecondary", http.StatusBadRequest)
		return
	}

	// Name the voting account. The node has one vote, belonging to the account
	// it stakes with, and casts it only for that wallet — so a webui unlocked
	// with a different wallet is told so instead of silently overwriting it.
	vote := append([]byte("VOTE"), MainWallet.MainAddress.GetBytes()...)
	reply := clientrpc.Call(SignMessage(append(vote, enb...)))

	jsonResponse(w, map[string]string{
		"success": "true",
		"message": string(reply),
	})
}

func ModifyEscrow(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}

	var req struct {
		EscrowDelay       int64  `json:"escrowDelay"`
		MultiSigNumber    int    `json:"multiSigNumber"`
		MultiSigAddresses string `json:"multiSigAddresses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.MultiSigNumber > 255 || req.MultiSigNumber < 0 {
		jsonError(w, "Multi-sig number must be between 0 and 255", http.StatusBadRequest)
		return
	}

	// Parse multi-sig addresses
	multiAddresses := [][common.AddressLength]byte{}
	if req.MultiSigAddresses != "" {
		addrs := strings.Split(req.MultiSigAddresses, ",")
		for _, addr := range addrs {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			addrb, err := hex.DecodeString(addr)
			if err != nil {
				jsonError(w, fmt.Sprintf("Invalid address hex: %s", addr), http.StatusBadRequest)
				return
			}
			if len(addrb) != common.AddressLength {
				jsonError(w, fmt.Sprintf("Address must be %d bytes: %s", common.AddressLength, addr), http.StatusBadRequest)
				return
			}
			ab := [20]byte{}
			copy(ab[:], addrb)
			multiAddresses = append(multiAddresses, ab)
		}
	}

	if len(multiAddresses) < req.MultiSigNumber {
		jsonError(w, fmt.Sprintf("Need at least %d addresses for multi-sig", req.MultiSigNumber), http.StatusBadRequest)
		return
	}

	// Public key
	// Two separate decisions, previously conflated into one flag.
	//
	// WHICH KEY TO REGISTER is the operator's choice: usePrimaryEncryption picks
	// the public key that travels in the transaction.
	//
	// WHICH KEY SIGNS is not a choice at all — it must be the scheme that is
	// live right now. The case that matters is registering the primary key
	// straight after a scheme replacement: that key arrives PAUSED and cannot
	// sign anything, so the spare (live precisely while the primary is paused)
	// has to sign for it. Leaving this to a checkbox meant the operator sent a
	// transaction signed with a paused scheme and got back nothing more useful
	// than "transaction fail to verify".
	SetCurrentEncryptions()
	signPrimary := !common.IsPaused()

	// No public key travels with an escrow change. Key registration belongs to
	// one place — the Send form — so that the operator has a single, obvious
	// route for it instead of the same option repeated on forms that have
	// nothing to do with keys.
	pk := common.PubKey{}

	// Build transaction
	txd := transactionsDefinition.TxData{
		Recipient:               MainWallet.MainAddress,
		Amount:                  0,
		OptData:                 []byte{},
		Pubkey:                  pk,
		EscrowTransactionsDelay: req.EscrowDelay,
		MultiSignNumber:         uint8(req.MultiSigNumber),
		MultiSignAddresses:      multiAddresses,
	}

	par := transactionsDefinition.TxParam{
		ChainID:     int16(23),
		Sender:      MainWallet.MainAddress,
		SendingTime: common.GetCurrentTimeStampInSecond(),
		Nonce:       common.RandomNonce(),
	}

	tx := transactionsDefinition.Transaction{
		TxData:    txd,
		TxParam:   par,
		Hash:      common.Hash{},
		Signature: common.Signature{},
		Height:    0,
		GasPrice:  int64(rand.Intn(0x0000000f)) + 1,
		GasUsage:  0,
	}

	// Get current height
	reply := clientrpc.Call(SignMessage([]byte("STAT")))
	sm := statistics.GetStatsManager()
	st := sm.Stats
	if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
		jsonError(w, "Failed to get network stats", http.StatusInternalServerError)
		return
	}

	tx.GasUsage = tx.GasUsageEstimate()
	tx.Height = st.Height

	if err := tx.CalcHashAndSet(); err != nil {
		jsonError(w, fmt.Sprintf("Failed to calculate hash: %v", err), http.StatusInternalServerError)
		return
	}

	if err := tx.Sign(MainWallet, signPrimary); err != nil {
		jsonError(w, fmt.Sprintf("Failed to sign transaction: %v", err), http.StatusInternalServerError)
		return
	}

	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to generate message: %v", err), http.StatusInternalServerError)
		return
	}

	tmm := msg.GetBytes()
	clientrpc.Call(SignMessage(append([]byte("TRAN"), tmm...)))

	jsonResponse(w, map[string]string{
		"success": "true",
		"txHash":  tx.Hash.GetHex(),
		"message": "Account modified successfully",
	})
}

func CallSmartContract(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Address   string `json:"address"`
		InputData string `json:"inputData"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	address := common.Address{}
	ba, err := hex.DecodeString(req.Address)
	if err != nil {
		jsonError(w, "Invalid address hex", http.StatusBadRequest)
		return
	}
	if err := address.Init(ba); err != nil {
		jsonError(w, "Invalid address", http.StatusBadRequest)
		return
	}

	optData := []byte{}
	if req.InputData != "" {
		optData, err = hex.DecodeString(req.InputData)
		if err != nil {
			jsonError(w, "Invalid input data hex", http.StatusBadRequest)
			return
		}
	}

	// Get current height
	reply := clientrpc.Call(SignMessage([]byte("STAT")))
	sm := statistics.GetStatsManager()
	st := sm.Stats
	if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
		jsonError(w, "Failed to get network stats", http.StatusInternalServerError)
		return
	}

	pf := blocks.PasiveFunction{
		Height:  st.Height,
		OptData: optData,
		Address: address,
	}

	b, _ := json.Marshal(pf)
	reply = clientrpc.Call(SignMessage(append([]byte("VIEW"), b...)))

	jsonResponse(w, map[string]string{
		"success": "true",
		"output":  hex.EncodeToString(reply),
	})
}

// solImportRE matches a Solidity import statement (WH-C1).
var solImportRE = regexp.MustCompile(`(?m)^\s*import\b`)

// sanitizeSolcError strips the temp directory path from compiler output so
// filesystem structure and any included file contents are not leaked (WH-H1).
func sanitizeSolcError(s, tmpDir string) string {
	s = strings.ReplaceAll(s, tmpDir+string(filepath.Separator), "")
	s = strings.ReplaceAll(s, tmpDir, "")
	const maxLen = 2000
	if len(s) > maxLen {
		s = s[:maxLen] + "…(truncated)"
	}
	return s
}

func CompileSmartContract(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Code == "" {
		jsonError(w, "No Solidity code provided", http.StatusBadRequest)
		return
	}
	const maxCodeSize = 512 * 1024 // 512 KB
	if len(req.Code) > maxCodeSize {
		jsonError(w, "Contract code too large (max 512 KB)", http.StatusBadRequest)
		return
	}
	// WH-C1: reject imports. Solidity `import` is the only way user code can pull
	// in external files (e.g. import "/etc/passwd"), so disallow it entirely. The
	// --base-path/--allow-paths confinement below is the defense-in-depth backstop.
	if solImportRE.MatchString(req.Code) {
		jsonError(w, "import statements are not allowed", http.StatusBadRequest)
		return
	}

	// Isolate the contract in its own directory so solc's base path can be
	// confined to it (WH-C1).
	tmpDir, err := os.MkdirTemp("", "qwid-solc-")
	if err != nil {
		jsonError(w, "Failed to create temp dir", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir)
	tmpPath := filepath.Join(tmpDir, "contract.sol")
	if err = os.WriteFile(tmpPath, []byte(req.Code), 0600); err != nil {
		jsonError(w, "Failed to write contract file", http.StatusInternalServerError)
		return
	}

	// solcArgs confines filesystem access to tmpDir: --base-path is the import
	// root and --allow-paths is the only extra readable location.
	solcArgs := func(flag string) []string {
		return []string{"--evm-version", "paris", "--base-path", tmpDir, "--allow-paths", tmpDir, flag, tmpPath}
	}

	// Compile bytecode
	cmd := exec.Command("solc", solcArgs("--bin")...)
	var binOut bytes.Buffer
	var binErr bytes.Buffer
	cmd.Stdout = &binOut
	cmd.Stderr = &binErr
	err = cmd.Run()
	if err != nil {
		// WH-H1: sanitize compiler output so absolute paths / file contents are
		// not leaked back to the client.
		jsonError(w, "Solidity compiler error: "+sanitizeSolcError(binErr.String(), tmpDir), http.StatusBadRequest)
		return
	}

	lines := strings.Split(binOut.String(), "\n")
	bytecode := ""
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if len(line) > 0 {
			bytecode = line
			break
		}
	}

	// Compile ABI
	cmd = exec.Command("solc", solcArgs("--abi")...)
	var abiOut bytes.Buffer
	var abiErr bytes.Buffer
	cmd.Stdout = &abiOut
	cmd.Stderr = &abiErr
	err = cmd.Run()
	if err != nil {
		jsonResponse(w, map[string]string{
			"bytecode": bytecode,
			"abi":      "",
			"warning":  "ABI generation failed: " + sanitizeSolcError(abiErr.String(), tmpDir),
		})
		return
	}

	abiLines := strings.Split(abiOut.String(), "\n")
	abiStr := ""
	for i := len(abiLines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(abiLines[i])
		if len(line) > 0 {
			abiStr = line
			break
		}
	}

	jsonResponse(w, map[string]string{
		"bytecode": bytecode,
		"abi":      abiStr,
	})
}

func GetFunctionSelector(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	selector := crypto.Keccak256([]byte(req.Signature))[:4]
	jsonResponse(w, map[string]string{
		"selector": hex.EncodeToString(selector),
	})
}

func GetDexInfo(w http.ResponseWriter, r *http.Request) {
	tokenAddr := r.URL.Query().Get("token")
	if tokenAddr == "" {
		jsonError(w, "Token address required", http.StatusBadRequest)
		return
	}

	coinAddr := common.Address{}
	ba, err := hex.DecodeString(tokenAddr)
	if err != nil {
		jsonError(w, "Invalid token address", http.StatusBadRequest)
		return
	}
	coinAddr.Init(ba)

	// Get DEX account info
	m := []byte("ADEX")
	m = append(m, coinAddr.GetBytes()...)
	reply := clientrpc.Call(SignMessage(m))

	poolInfo := map[string]interface{}{}
	if len(reply) > 8 {
		dexAcc := account.DexAccount{}
		if err := dexAcc.Unmarshal(reply); err == nil {
			poolInfo["tokenPool"] = account.Int64toFloat64(dexAcc.TokenPool)
			poolInfo["coinPool"] = account.Int64toFloat64(dexAcc.CoinPool)
		}
	}

	holdings := map[string]interface{}{}
	if walletReady() {
		// Get token balance
		m = []byte("GTBL")
		m = append(m, MainWallet.MainAddress.GetBytes()...)
		m = append(m, coinAddr.GetBytes()...)
		reply = clientrpc.Call(SignMessage(m))
		if len(reply) == 32 {
			holdings["tokenBalance"] = account.Int64toFloat64(common.GetInt64FromSCByte(reply))
		}
	}

	jsonResponse(w, map[string]interface{}{
		"pool":     poolInfo,
		"holdings": holdings,
	})
}

func ExecuteDex(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}

	var req struct {
		TokenAddress         string  `json:"tokenAddress"`
		Operation            string  `json:"operation"` // addLiquidity, withdrawToken, withdrawQWD, trade
		TokenAmount          float64 `json:"tokenAmount"`
		QwdAmount            float64 `json:"qwdAmount"`
		UsePrimaryEncryption bool    `json:"usePrimaryEncryption"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	coinAddr := common.Address{}
	ba, err := hex.DecodeString(req.TokenAddress)
	if err != nil {
		jsonError(w, "Invalid token address", http.StatusBadRequest)
		return
	}
	coinAddr.Init(ba)

	// Determine operation code
	var operation int
	switch req.Operation {
	case "addLiquidity":
		operation = 2
	case "withdrawToken":
		operation = 5
	case "withdrawQWD":
		operation = 6
	default:
		jsonError(w, "Invalid operation", http.StatusBadRequest)
		return
	}

	tokenAm := common.CoinToBaseUnits(req.TokenAmount)
	qwdAm := common.CoinToBaseUnits(req.QwdAmount)

	sender := common.Address{}
	sender.Init(append([]byte{0}, MainWallet.MainAddress.GetBytes()...))

	ar := common.GetDelegatedAccountAddress(int16(512 + operation))
	txd := transactionsDefinition.TxData{
		Recipient:                  ar,
		Amount:                     qwdAm,
		OptData:                    common.GetByteInt64(tokenAm),
		Pubkey:                     common.PubKey{},
		LockedAmount:               0,
		ReleasePerBlock:            0,
		DelegatedAccountForLocking: common.GetDelegatedAccountAddress(1),
	}

	par := transactionsDefinition.TxParam{
		ChainID:     int16(23),
		Sender:      sender,
		SendingTime: common.GetCurrentTimeStampInSecond(),
		Nonce:       common.RandomNonce(),
	}

	tx := transactionsDefinition.Transaction{
		TxData:          txd,
		TxParam:         par,
		Hash:            common.Hash{},
		Signature:       common.Signature{},
		Height:          0,
		GasPrice:        int64(rand.Intn(0x0000000f)) + 1,
		GasUsage:        0,
		ContractAddress: coinAddr,
	}

	// Get current height
	reply := clientrpc.Call(SignMessage([]byte("STAT")))
	sm := statistics.GetStatsManager()
	st := sm.Stats
	if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
		jsonError(w, "Failed to get network stats", http.StatusInternalServerError)
		return
	}

	tx.Height = st.Height
	tx.GasUsage = tx.GasUsageEstimate()

	if err := tx.CalcHashAndSet(); err != nil {
		jsonError(w, fmt.Sprintf("Failed to calculate hash: %v", err), http.StatusInternalServerError)
		return
	}

	if err := tx.Sign(MainWallet, req.UsePrimaryEncryption); err != nil {
		jsonError(w, fmt.Sprintf("Failed to sign transaction: %v", err), http.StatusInternalServerError)
		return
	}

	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to generate message: %v", err), http.StatusInternalServerError)
		return
	}

	tmm := msg.GetBytes()
	clientrpc.Call(SignMessage(append([]byte("TRAN"), tmm...)))

	jsonResponse(w, map[string]string{
		"success": "true",
		"txHash":  tx.Hash.GetHex(),
		"message": "DEX operation completed",
	})
}

func TradeDex(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}

	var req struct {
		TokenAddress         string  `json:"tokenAddress"`
		Action               string  `json:"action"` // buy or sell
		Amount               float64 `json:"amount"`
		UsePrimaryEncryption bool    `json:"usePrimaryEncryption"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	coinAddr := common.Address{}
	ba, err := hex.DecodeString(req.TokenAddress)
	if err != nil {
		jsonError(w, "Invalid token address", http.StatusBadRequest)
		return
	}
	coinAddr.Init(ba)

	var operation int
	if req.Action == "buy" {
		operation = 3
	} else if req.Action == "sell" {
		operation = 4
	} else {
		jsonError(w, "Invalid action: use 'buy' or 'sell'", http.StatusBadRequest)
		return
	}

	am := common.CoinToBaseUnits(req.Amount)

	sender := common.Address{}
	sender.Init(append([]byte{0}, MainWallet.MainAddress.GetBytes()...))

	ar := common.GetDelegatedAccountAddress(int16(512 + operation))
	txd := transactionsDefinition.TxData{
		Recipient:                  ar,
		Amount:                     am,
		OptData:                    common.GetByteInt64(am),
		Pubkey:                     common.PubKey{},
		LockedAmount:               0,
		ReleasePerBlock:            0,
		DelegatedAccountForLocking: common.GetDelegatedAccountAddress(1),
	}

	par := transactionsDefinition.TxParam{
		ChainID:     int16(23),
		Sender:      sender,
		SendingTime: common.GetCurrentTimeStampInSecond(),
		Nonce:       common.RandomNonce(),
	}

	tx := transactionsDefinition.Transaction{
		TxData:          txd,
		TxParam:         par,
		Hash:            common.Hash{},
		Signature:       common.Signature{},
		Height:          0,
		GasPrice:        int64(rand.Intn(0x0000000f)) + 1,
		GasUsage:        0,
		ContractAddress: coinAddr,
	}

	// Get current height
	reply := clientrpc.Call(SignMessage([]byte("STAT")))
	sm := statistics.GetStatsManager()
	st := sm.Stats
	if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
		jsonError(w, "Failed to get network stats", http.StatusInternalServerError)
		return
	}

	tx.Height = st.Height
	tx.GasUsage = tx.GasUsageEstimate()

	if err := tx.CalcHashAndSet(); err != nil {
		jsonError(w, fmt.Sprintf("Failed to calculate hash: %v", err), http.StatusInternalServerError)
		return
	}

	if err := tx.Sign(MainWallet, req.UsePrimaryEncryption); err != nil {
		jsonError(w, fmt.Sprintf("Failed to sign transaction: %v", err), http.StatusInternalServerError)
		return
	}

	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to generate message: %v", err), http.StatusInternalServerError)
		return
	}

	tmm := msg.GetBytes()
	clientrpc.Call(SignMessage(append([]byte("TRAN"), tmm...)))

	jsonResponse(w, map[string]string{
		"success": "true",
		"txHash":  tx.Hash.GetHex(),
		"message": fmt.Sprintf("%s order completed", req.Action),
	})
}

// GetPeers returns information about connected and banned peers
func GetPeers(w http.ResponseWriter, r *http.Request) {
	reply := clientrpc.Call(SignMessage([]byte("PEER")))
	if bytes.Equal(reply, []byte("Timeout")) {
		jsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(reply, &resp); err != nil {
		jsonError(w, "Failed to parse peer info", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, resp)
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// GetLogFiles returns list of available log files
func GetLogFiles(w http.ResponseWriter, r *http.Request) {
	homePath, err := getHomeDir()
	if err != nil {
		jsonError(w, "Cannot get home directory", http.StatusInternalServerError)
		return
	}

	logsDir := homePath + "/.qwid/logs/"
	files, err := getLogFileList(logsDir)
	if err != nil {
		jsonError(w, fmt.Sprintf("Cannot read logs directory: %v", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"files": files,
	})
}

// GetLogs returns log content with filtering
func GetLogs(w http.ResponseWriter, r *http.Request) {
	homePath, err := getHomeDir()
	if err != nil {
		jsonError(w, "Cannot get home directory", http.StatusInternalServerError)
		return
	}

	logsDir := homePath + "/.qwid/logs/"

	// Get parameters
	fileName := r.URL.Query().Get("file")
	filter := r.URL.Query().Get("filter")
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")

	offset := 0
	limit := 500 // default limit
	if offsetStr != "" {
		offset, _ = strconv.Atoi(offsetStr)
	}
	if limitStr != "" {
		limit, _ = strconv.Atoi(limitStr)
	}
	if limit > 5000 {
		limit = 5000 // max limit
	}

	// If no file specified, use today's log
	if fileName == "" {
		fileName = "mining-" + getCurrentDate() + ".log"
	}

	// Prevent path traversal: strip all directory components, then verify the
	// resolved path stays inside logsDir.
	cleanedLogsDir := filepath.Clean(logsDir)
	filePath := filepath.Join(cleanedLogsDir, filepath.Base(fileName))
	if !strings.HasPrefix(filePath, cleanedLogsDir+string(filepath.Separator)) {
		jsonError(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	// Read log file
	content, totalLines, err := readLogFile(filePath, filter, offset, limit)
	if err != nil {
		jsonError(w, fmt.Sprintf("Cannot read log file: %v", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"lines":      content,
		"totalLines": totalLines,
		"offset":     offset,
		"limit":      limit,
		"file":       fileName,
		"filter":     filter,
	})
}

func getHomeDir() (string, error) {
	homePath := ""
	if h, err := getUserHomeDir(); err == nil {
		homePath = h
	}
	return homePath, nil
}

func getUserHomeDir() (string, error) {
	return getHomeDirImpl()
}

func getHomeDirImpl() (string, error) {
	// Use os.UserHomeDir
	return osUserHomeDir()
}

func osUserHomeDir() (string, error) {
	return getEnvHome(), nil
}

func getEnvHome() string {
	home := getEnv("HOME")
	if home == "" {
		home = "/root"
	}
	return home
}

func getEnv(key string) string {
	return envGet(key)
}

func envGet(key string) string {
	// Simple env lookup - in real code use os.Getenv
	return lookupEnv(key)
}

func lookupEnv(key string) string {
	// Import os is already in the file through logger package
	// Use a simple implementation
	if key == "HOME" {
		// Get home from user home dir utility
		return getUserHomePath()
	}
	return ""
}

func getUserHomePath() string {
	// Use the same path as logger package
	return getHomePath()
}

func getHomePath() string {
	home, _ := osGetUserHomeDir()
	return home
}

func osGetUserHomeDir() (string, error) {
	return osUserHomeDirImpl()
}

func osUserHomeDirImpl() (string, error) {
	// We need to import os, but since we have issues let's use the logger path
	// Logger uses os.UserHomeDir internally
	// For now, hardcode common paths
	return detectHomeDir(), nil
}

func detectHomeDir() string {
	// Try common environment variable
	// Since we cannot easily import os here without circular issues,
	// Use a simpler approach - the logger already sets up paths
	return logger.GetHomePath()
}

func getCurrentDate() string {
	return getCurrentTimeDate()
}

func getCurrentTimeDate() string {
	return getTimeNowDate()
}

func getTimeNowDate() string {
	return formatTimeDate()
}

func formatTimeDate() string {
	return getFormattedDate()
}

func getFormattedDate() string {
	return common.GetCurrentDate()
}

func getLogFileList(dir string) ([]string, error) {
	return listLogFiles(dir)
}

func listLogFiles(dir string) ([]string, error) {
	return readDirLogFiles(dir)
}

func readDirLogFiles(dir string) ([]string, error) {
	return getDirLogFiles(dir)
}

func getDirLogFiles(dir string) ([]string, error) {
	return fetchLogFileNames(dir)
}

func fetchLogFileNames(dir string) ([]string, error) {
	return loadLogFileList(dir)
}

func loadLogFileList(dir string) ([]string, error) {
	return getLogFilesFromDir(dir)
}

func getLogFilesFromDir(dir string) ([]string, error) {
	return scanLogDir(dir)
}

func scanLogDir(dir string) ([]string, error) {
	return findLogFiles(dir)
}

func findLogFiles(dir string) ([]string, error) {
	return logger.GetLogFiles(dir)
}

func readLogFile(path, filter string, offset, limit int) ([]string, int, error) {
	return loadLogContent(path, filter, offset, limit)
}

func loadLogContent(path, filter string, offset, limit int) ([]string, int, error) {
	return fetchLogLines(path, filter, offset, limit)
}

func fetchLogLines(path, filter string, offset, limit int) ([]string, int, error) {
	return getLogLines(path, filter, offset, limit)
}

func getLogLines(path, filter string, offset, limit int) ([]string, int, error) {
	return readLogLines(path, filter, offset, limit)
}

func readLogLines(path, filter string, offset, limit int) ([]string, int, error) {
	return logger.ReadLogFile(path, filter, offset, limit)
}

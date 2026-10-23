package handlers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/recoveryplan"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/services/transactionServices"
	"github.com/qwid-org/qwid-node/statistics"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/wallet"
)

// The Recovery tab runs what cmd/recoverKey does - prepare, bind, reveal -
// from the browser. Everything secret (the phrase, the recovery secret, the
// old address key) stays in the loaded wallet on this machine: the browser
// only ever sees hashes and the transactions' outcome.

// defaultRecoverySchemes are the built-in schemes, captured at package
// initialisation - before the chain's are installed - because an old
// account's address may come from a key of one of them.
var defaultRecoverySchemes = []string{common.SigName(), common.SigName2()}

func pubaKeys(addr common.Address) (wallet.RegisteredKeys, error) {
	return wallet.ParsePUBA(clientrpc.Call(SignMessage(append([]byte("PUBA"), addr.GetBytes()...))))
}

// planForMainWallet plans the loaded wallet's recovery under the chain's
// current schemes.
func planForMainWallet() (recoveryplan.Plan, error) {
	SetCurrentEncryptions()
	keys, err := pubaKeys(MainWallet.MainAddress)
	if err != nil {
		return recoveryplan.Plan{}, fmt.Errorf("cannot ask the node about this identity: %v", err)
	}
	return recoveryplan.Make(MainWallet, keys, common.IsPaused(), defaultRecoverySchemes)
}

type bindStatus struct {
	Exists    bool  `json:"exists"`
	Height    int64 `json:"height,omitempty"`
	ReadyAt   int64 `json:"readyAt,omitempty"`
	ExpiresAt int64 `json:"expiresAt,omitempty"`
}

func bindOnChain(key [32]byte) bindStatus {
	var b bindStatus
	_ = json.Unmarshal(clientrpc.Call(SignMessage(append([]byte("RBND"), key[:]...))), &b)
	return b
}

func chainHeight() (int64, error) {
	st := statistics.GetStatsManager().Stats
	if err := common.Unmarshal(clientrpc.Call(SignMessage([]byte("STAT"))), common.StatDBPrefix, &st); err != nil {
		return 0, err
	}
	return st.Height, nil
}

// RecoveryStatus says whether the loaded wallet's account needs recovering,
// by which route, and where its bind stands.
func RecoveryStatus(w http.ResponseWriter, r *http.Request) {
	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}
	resp := map[string]interface{}{
		"identity":    MainWallet.MainAddress.GetHex(),
		"bindAddress": common.RecoveryBindAddress.GetHex(),
		"delayBlocks": common.RecoveryBindDelayBlocks,
	}
	if h, err := chainHeight(); err == nil {
		resp["height"] = h
	}
	p, err := planForMainWallet()
	if err != nil {
		resp["mode"] = "none"
		resp["reason"] = err.Error()
		jsonResponse(w, resp)
		return
	}
	resp["mode"] = map[bool]string{true: "address", false: "commitment"}[p.AddressMode]
	resp["newKey"] = p.NewKey.Address.GetHex()
	resp["newKeyScheme"] = map[bool]string{true: common.SigName(), false: common.SigName2()}[p.SlotPrimary]
	if p.AddressMode {
		resp["oldScheme"] = p.OldScheme
	}
	resp["bindData"] = hex.EncodeToString(p.BindData)
	resp["bind"] = bindOnChain(p.BindKey)
	jsonResponse(w, resp)
}

// recoveryTx builds, signs with signer's key in slot primary and submits a
// recovery transaction.
func recoveryTx(signer *wallet.Wallet, recipient common.Address, opt []byte, pk common.PubKey, primary bool) (string, error) {
	h, err := chainHeight()
	if err != nil {
		return "", fmt.Errorf("cannot read the chain height: %v", err)
	}
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: signer.MainAddress,
			SendingTime: common.GetCurrentTimeStampInSecond(), Nonce: common.RandomNonce()},
		TxData:   transactionsDefinition.TxData{Recipient: recipient, OptData: opt, Pubkey: pk},
		Height:   h,
		GasPrice: int64(rand.Intn(0x0000000f)) + 1,
	}
	tx.GasUsage = tx.GasUsageEstimate()
	if err := tx.CalcHashAndSet(); err != nil {
		return "", err
	}
	if err := tx.Sign(signer, primary); err != nil {
		return "", err
	}
	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		return "", err
	}
	if err := clientrpc.SubmitTransaction(SignMessage(append([]byte("TRAN"), msg.GetBytes()...))); err != nil {
		return "", err
	}
	return tx.Hash.GetHex(), nil
}

// RecoveryBind sends phase 1 - the bind - paid and signed by another wallet
// on this machine that can still send (the account being recovered usually
// cannot). That wallet is loaded only to sign and is wiped right after; the
// wallet loaded in the session is untouched.
func RecoveryBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}
	var req struct {
		PayerWallet   int    `json:"payerWallet"`
		PayerPassword string `json:"payerPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PayerWallet < 0 || req.PayerWallet > 255 {
		jsonError(w, "Give the number (0-255) and password of the wallet that pays for the bind", http.StatusBadRequest)
		return
	}
	p, err := planForMainWallet()
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if b := bindOnChain(p.BindKey); b.Exists {
		jsonError(w, fmt.Sprintf("the bind is already on chain (block %d); the reveal is possible from block %d", b.Height, b.ReadyAt), http.StatusConflict)
		return
	}
	payer := MainWallet
	if uint8(req.PayerWallet) != MainWallet.WalletNumber {
		sigName, sigName2, err := SetCurrentEncryptions()
		if err != nil {
			jsonError(w, "Cannot read the chain's signature schemes", http.StatusInternalServerError)
			return
		}
		payer, err = wallet.LoadJSON(uint8(req.PayerWallet), req.PayerPassword, sigName, sigName2)
		if err != nil {
			jsonError(w, "Cannot open the paying wallet: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer payer.Wipe()
	}
	if bytes.Equal(payer.MainAddress.GetBytes(), MainWallet.MainAddress.GetBytes()) && payer != MainWallet {
		jsonError(w, "The paying wallet is this same identity; choose a wallet that can still send", http.StatusBadRequest)
		return
	}
	txHash, err := recoveryTx(payer, common.RecoveryBindAddress, p.BindData, common.PubKey{}, !common.IsPaused())
	if err != nil {
		jsonError(w, "The bind was refused: "+err.Error(), http.StatusBadGateway)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"success": true, "txHash": txHash, "payer": payer.MainAddress.GetHex(),
		"message": fmt.Sprintf("Bind sent. The reveal becomes possible %d blocks after it is included.", common.RecoveryBindDelayBlocks),
	})
}

// RecoveryReveal sends phase 2 - the reveal - from the account itself,
// signed by its new key: it registers that key and sets the next commitments.
func RecoveryReveal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !walletReady() {
		jsonError(w, "Load wallet first", http.StatusBadRequest)
		return
	}
	p, err := planForMainWallet()
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	b := bindOnChain(p.BindKey)
	if !b.Exists {
		jsonError(w, "No bind on chain yet: send the bind first, and wait until it is included", http.StatusConflict)
		return
	}
	if h, err := chainHeight(); err == nil && h+1 < b.ReadyAt {
		jsonError(w, fmt.Sprintf("Too early: the reveal is possible from block %d (now %d, %d blocks to go)", b.ReadyAt, h, b.ReadyAt-h-1), http.StatusConflict)
		return
	}
	txHash, err := recoveryTx(MainWallet, common.RecoveryRevealAddress, p.RevealOptData(), p.NewKey, p.SlotPrimary)
	if err != nil {
		jsonError(w, "The reveal was refused: "+err.Error(), http.StatusBadGateway)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"success": true, "txHash": txHash,
		"message": "Reveal sent. When it is in a block, your new key is registered; check the Account tab.",
	})
}

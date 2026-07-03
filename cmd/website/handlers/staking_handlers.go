package handlers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	clientrpc "github.com/wonabru/qwid-node/rpc/client"
	"github.com/wonabru/qwid-node/services/transactionServices"
	"github.com/wonabru/qwid-node/statistics"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

func ExecuteStaking(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		JsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess := GetSession(r.Context())
	if sess == nil || sess.Wallet == nil {
		JsonError(w, "Wallet not loaded", http.StatusBadRequest)
		return
	}

	wl := sess.Wallet

	var req struct {
		Action               string  `json:"action"`
		DelegatedAccount     string  `json:"delegatedAccount"`
		Amount               float64 `json:"amount"`
		IntendOperator       bool    `json:"intendOperator"`
		IncludePubKey        bool    `json:"includePubKey"`
		UsePrimaryEncryption bool    `json:"usePrimaryEncryption"`
		TargetOperator       string  `json:"targetOperator"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ar := common.Address{}
	di, err := strconv.ParseInt(req.DelegatedAccount, 10, 16)
	if err != nil {
		bar, err := hex.DecodeString(req.DelegatedAccount)
		if err != nil {
			JsonError(w, "Invalid delegated account", http.StatusBadRequest)
			return
		}
		if err := ar.Init(bar); err != nil {
			JsonError(w, "Invalid delegated account address", http.StatusBadRequest)
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
		JsonError(w, fmt.Sprintf("Invalid delegated account: %s", ar.GetHex()), http.StatusBadRequest)
		return
	}

	if req.Amount <= 0 {
		JsonError(w, "Amount must be greater than 0", http.StatusBadRequest)
		return
	}

	am := common.CoinToBaseUnits(req.Amount)

	if req.Action == "stake" && am < common.MinStakingUser {
		JsonError(w, fmt.Sprintf("Minimum staking amount is %f", float64(common.MinStakingUser)/1e8), http.StatusBadRequest)
		return
	}

	if req.Action == "unstake" || req.Action == "withdraw" {
		am *= -1
	}

	optData := []byte{}
	if req.IntendOperator {
		optData = []byte{1}
	}

	pk := common.PubKey{}
	primary := req.UsePrimaryEncryption
	if req.IncludePubKey {
		if primary {
			pk = wl.Account1.PublicKey
		} else {
			pk = wl.Account2.PublicKey
		}
	}

	var recipient common.Address
	var lockedAmount int64
	var releasePerBlock int64
	var delegatedAccountForLocking common.Address

	if req.TargetOperator != "" && req.Action == "stake" {
		targetBytes, err := hex.DecodeString(req.TargetOperator)
		if err != nil || len(targetBytes) != common.AddressLength {
			JsonError(w, "Invalid target operator address", http.StatusBadRequest)
			return
		}
		recipient = common.Address{}
		if err := recipient.Init(append([]byte{1}, targetBytes...)); err != nil {
			JsonError(w, "Failed to init target operator address", http.StatusBadRequest)
			return
		}
		lockedAmount = am
		releasePerBlock = am
		delegatedAccountForLocking = ar
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
		Sender:      wl.MainAddress,
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

	clientrpc.InRPC <- SignMessage([]byte("STAT"))
	reply := <-clientrpc.OutRPC
	if bytes.Equal(reply, []byte("Timeout")) {
		JsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}
	sm := statistics.GetStatsManager()
	st := sm.Stats
	if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
		JsonError(w, "Failed to get network stats", http.StatusInternalServerError)
		return
	}

	tx.GasUsage = tx.GasUsageEstimate()
	tx.Height = st.Height

	if err := tx.CalcHashAndSet(); err != nil {
		JsonError(w, fmt.Sprintf("Failed to calculate hash: %v", err), http.StatusInternalServerError)
		return
	}

	if err := tx.Sign(wl, primary); err != nil {
		JsonError(w, fmt.Sprintf("Failed to sign transaction: %v", err), http.StatusInternalServerError)
		return
	}

	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		JsonError(w, fmt.Sprintf("Failed to generate message: %v", err), http.StatusInternalServerError)
		return
	}

	tmm := msg.GetBytes()
	clientrpc.InRPC <- SignMessage(append([]byte("TRAN"), tmm...))
	<-clientrpc.OutRPC

	JsonResponse(w, map[string]string{
		"success": "true",
		"txHash":  tx.Hash.GetHex(),
		"message": "Staking transaction sent successfully",
	})
}

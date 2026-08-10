package handlers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/services/transactionServices"
	"github.com/qwid-org/qwid-node/statistics"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func GetTokens(w http.ResponseWriter, r *http.Request) {
	reply := clientrpc.Call(SignMessage([]byte("LTKN")))
	if bytes.Equal(reply, []byte("Timeout")) {
		JsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	var tokens map[string]interface{}
	if err := json.Unmarshal(reply, &tokens); err != nil {
		JsonResponse(w, map[string]interface{}{"tokens": map[string]interface{}{}})
		return
	}
	JsonResponse(w, map[string]interface{}{"tokens": tokens})
}

func GetDexInfo(w http.ResponseWriter, r *http.Request) {
	tokenAddr := r.URL.Query().Get("token")
	if tokenAddr == "" {
		JsonError(w, "Token address required", http.StatusBadRequest)
		return
	}

	coinAddr := common.Address{}
	ba, err := hex.DecodeString(tokenAddr)
	if err != nil {
		JsonError(w, "Invalid token address", http.StatusBadRequest)
		return
	}
	coinAddr.Init(ba)

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
	sess := GetSession(r.Context())
	if sess != nil && sess.Wallet != nil {
		wl := sess.Wallet
		m = []byte("GTBL")
		m = append(m, wl.MainAddress.GetBytes()...)
		m = append(m, coinAddr.GetBytes()...)
		reply = clientrpc.Call(SignMessage(m))
		if len(reply) == 32 {
			holdings["tokenBalance"] = account.Int64toFloat64(common.GetInt64FromSCByte(reply))
		}
	}

	JsonResponse(w, map[string]interface{}{
		"pool":     poolInfo,
		"holdings": holdings,
	})
}

func TradeDex(w http.ResponseWriter, r *http.Request) {
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
		TokenAddress         string  `json:"tokenAddress"`
		Action               string  `json:"action"`
		Amount               float64 `json:"amount"`
		UsePrimaryEncryption bool    `json:"usePrimaryEncryption"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	coinAddr := common.Address{}
	ba, err := hex.DecodeString(req.TokenAddress)
	if err != nil {
		JsonError(w, "Invalid token address", http.StatusBadRequest)
		return
	}
	coinAddr.Init(ba)

	var operation int
	if req.Action == "buy" {
		operation = 3
	} else if req.Action == "sell" {
		operation = 4
	} else {
		JsonError(w, "Invalid action: use 'buy' or 'sell'", http.StatusBadRequest)
		return
	}

	am := common.CoinToBaseUnits(req.Amount)

	sender := common.Address{}
	sender.Init(append([]byte{0}, wl.MainAddress.GetBytes()...))

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

	reply := clientrpc.Call(SignMessage([]byte("STAT")))
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

	tx.Height = st.Height
	tx.GasUsage = tx.GasUsageEstimate()

	if err := tx.CalcHashAndSet(); err != nil {
		JsonError(w, fmt.Sprintf("Failed to calculate hash: %v", err), http.StatusInternalServerError)
		return
	}

	primary := !common.IsPaused()
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
	clientrpc.Call(SignMessage(append([]byte("TRAN"), tmm...)))

	JsonResponse(w, map[string]string{
		"success": "true",
		"txHash":  tx.Hash.GetHex(),
		"message": fmt.Sprintf("%s order completed", req.Action),
	})
}

func ExecuteDex(w http.ResponseWriter, r *http.Request) {
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
		TokenAddress         string  `json:"tokenAddress"`
		Operation            string  `json:"operation"`
		TokenAmount          float64 `json:"tokenAmount"`
		QwdAmount            float64 `json:"qwdAmount"`
		UsePrimaryEncryption bool    `json:"usePrimaryEncryption"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	coinAddr := common.Address{}
	ba, err := hex.DecodeString(req.TokenAddress)
	if err != nil {
		JsonError(w, "Invalid token address", http.StatusBadRequest)
		return
	}
	coinAddr.Init(ba)

	var operation int
	switch req.Operation {
	case "addLiquidity":
		operation = 2
	case "withdrawToken":
		operation = 5
	case "withdrawQWD":
		operation = 6
	default:
		JsonError(w, "Invalid operation", http.StatusBadRequest)
		return
	}

	tokenAm := common.CoinToBaseUnits(req.TokenAmount)
	qwdAm := common.CoinToBaseUnits(req.QwdAmount)

	sender := common.Address{}
	sender.Init(append([]byte{0}, wl.MainAddress.GetBytes()...))

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

	reply := clientrpc.Call(SignMessage([]byte("STAT")))
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

	tx.Height = st.Height
	tx.GasUsage = tx.GasUsageEstimate()

	if err := tx.CalcHashAndSet(); err != nil {
		JsonError(w, fmt.Sprintf("Failed to calculate hash: %v", err), http.StatusInternalServerError)
		return
	}

	primary := !common.IsPaused()
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
	clientrpc.Call(SignMessage(append([]byte("TRAN"), tmm...)))

	JsonResponse(w, map[string]string{
		"success": "true",
		"txHash":  tx.Hash.GetHex(),
		"message": "DEX operation completed",
	})
}

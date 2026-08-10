package handlers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	clientrpc "github.com/wonabru/qwid-node/rpc/client"
	"github.com/wonabru/qwid-node/services/transactionServices"
	"github.com/wonabru/qwid-node/statistics"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

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
}

func GetStats(w http.ResponseWriter, r *http.Request) {
	reply := clientrpc.Call(SignMessage([]byte("STAT")))
	if bytes.Equal(reply, []byte("Timeout")) {
		JsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	sm := statistics.GetStatsManager()
	st := sm.Stats
	if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
		JsonError(w, "Failed to unmarshal stats", http.StatusInternalServerError)
		return
	}

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
	}
	JsonResponse(w, resp)
}

func GetDetails(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		JsonError(w, "Hash parameter required", http.StatusBadRequest)
		return
	}

	var b []byte
	var err error
	if len(hash) < 16 {
		height, err := strconv.Atoi(hash)
		if err != nil {
			JsonError(w, "Invalid height format", http.StatusBadRequest)
			return
		}
		b = common.GetByteInt64(int64(height))
	} else {
		b, err = hex.DecodeString(hash)
		if err != nil {
			JsonError(w, "Invalid hash format", http.StatusBadRequest)
			return
		}
	}

	reply := clientrpc.Call(SignMessage(append([]byte("DETS"), b...)))
	if len(reply) <= 2 {
		JsonError(w, "Not found", http.StatusNotFound)
		return
	}

	switch string(reply[:2]) {
	case "TX":
		if len(reply) < 3 {
			JsonError(w, "Transaction not found", http.StatusNotFound)
			return
		}
		locLen := int(reply[2])
		if len(reply) < 3+locLen {
			JsonError(w, "Invalid response format", http.StatusInternalServerError)
			return
		}
		location := string(reply[3 : 3+locLen])
		tx := transactionsDefinition.Transaction{}
		tx, _, err := tx.GetFromBytes(reply[3+locLen:])
		if err != nil {
			JsonError(w, "Failed to parse transaction", http.StatusInternalServerError)
			return
		}
		JsonResponse(w, map[string]interface{}{
			"type":     "transaction",
			"data":     tx.GetString(),
			"location": location,
		})
	case "AC":
		var acc account.Account
		if err := acc.Unmarshal(reply[2:]); err != nil {
			JsonError(w, "Failed to parse account", http.StatusInternalServerError)
			return
		}
		transactions := []map[string]interface{}{}
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
		addr := common.Address{}
		addr.Init(acc.Address[:])
		JsonResponse(w, map[string]interface{}{
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
			JsonError(w, "Failed to parse block", http.StatusInternalServerError)
			return
		}
		JsonResponse(w, map[string]interface{}{
			"type": "block",
			"data": bb.GetString(),
		})
	default:
		JsonResponse(w, map[string]interface{}{
			"type": "unknown",
			"data": string(reply),
		})
	}
}

func SendTransaction(w http.ResponseWriter, r *http.Request) {
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
		Recipient            string  `json:"recipient"`
		Amount               float64 `json:"amount"`
		IncludePubKey        bool    `json:"includePubKey"`
		UsePrimaryEncryption bool    `json:"usePrimaryEncryption"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ar := common.Address{}
	if len(req.Recipient) < 20 {
		i, err := strconv.Atoi(req.Recipient)
		if err != nil || i > 255 {
			JsonError(w, "Invalid delegated account number", http.StatusBadRequest)
			return
		}
		ar = common.GetDelegatedAccountAddress(int16(i))
	} else {
		bar, err := hex.DecodeString(req.Recipient)
		if err != nil {
			JsonError(w, "Invalid recipient address hex", http.StatusBadRequest)
			return
		}
		if err := ar.Init(bar); err != nil {
			JsonError(w, "Invalid recipient address", http.StatusBadRequest)
			return
		}
	}

	if req.Amount < 0 {
		JsonError(w, "Amount cannot be negative", http.StatusBadRequest)
		return
	}

	// Reject regular transfers to delegated accounts — use staking API instead
	if n, err := account.IntDelegatedAccountFromAddress(ar); err == nil && n > 0 {
		JsonError(w, "Cannot send regular transfer to delegated account. Use staking operations instead.", http.StatusBadRequest)
		return
	}

	am := common.CoinToBaseUnits(req.Amount)

	pk := common.PubKey{}
	primary := req.UsePrimaryEncryption
	if req.IncludePubKey {
		if primary {
			pk = wl.Account1.PublicKey
		} else {
			pk = wl.Account2.PublicKey
		}
	}

	txd := transactionsDefinition.TxData{
		Recipient:                  ar,
		Amount:                     am,
		OptData:                    []byte{},
		Pubkey:                     pk,
		LockedAmount:               0,
		ReleasePerBlock:            0,
		DelegatedAccountForLocking: common.GetDelegatedAccountAddress(1),
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

	reply := clientrpc.Call(SignMessage([]byte("STAT")))
	sm := statistics.GetStatsManager()
	st := sm.Stats
	if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
		JsonError(w, "Failed to get network stats", http.StatusInternalServerError)
		return
	}

	tx.GasUsage = tx.GasUsageEstimate()
	tx.Height = st.Height

	if err := tx.CalcHashAndSet(); err != nil {
		JsonError(w, "Failed to calculate hash", http.StatusInternalServerError)
		return
	}

	if err := tx.Sign(wl, primary); err != nil {
		JsonError(w, "Failed to sign transaction", http.StatusInternalServerError)
		return
	}

	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		JsonError(w, "Failed to generate message", http.StatusInternalServerError)
		return
	}

	tmm := msg.GetBytes()
	clientrpc.Call(SignMessage(append([]byte("TRAN"), tmm...)))

	JsonResponse(w, map[string]string{
		"success": "true",
		"txHash":  tx.Hash.GetHex(),
		"message": "Transaction sent successfully",
	})
}

func GetHistory(w http.ResponseWriter, r *http.Request) {
	sess := GetSession(r.Context())
	if sess == nil || sess.Wallet == nil {
		JsonError(w, "Wallet not loaded", http.StatusBadRequest)
		return
	}

	wl := sess.Wallet
	inb := append([]byte("ACCT"), wl.MainAddress.GetBytes()...)
	re := clientrpc.Call(SignMessage(inb))
	if bytes.Equal(re, []byte("Timeout")) {
		JsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	var acc account.Account
	if err := acc.Unmarshal(re); err != nil {
		JsonError(w, "Failed to unmarshal account", http.StatusInternalServerError)
		return
	}

	transactions := []map[string]interface{}{}

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
					})
				}
			}
		}
	}

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
						"type":   "received",
						"hash":   tx.Hash.GetHex(),
						"sender": tx.TxParam.Sender.GetHex(),
						"amount": account.Int64toFloat64(tx.TxData.Amount),
						"height": tx.Height,
						"time":   tx.TxParam.SendingTime,
					})
				}
			}
		}
	}

	JsonResponse(w, map[string]interface{}{
		"transactions": transactions,
		"address":      wl.MainAddress.GetHex(),
	})
}

func GetPending(w http.ResponseWriter, r *http.Request) {
	reply := clientrpc.Call(SignMessage([]byte("PEND")))
	if bytes.Equal(reply, []byte("Timeout")) {
		JsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	transactions := []map[string]interface{}{}
	if len(reply) > 0 {
		var txList []map[string]interface{}
		if err := json.Unmarshal(reply, &txList); err == nil {
			transactions = txList
		} else {
			JsonResponse(w, map[string]interface{}{
				"raw":   hex.EncodeToString(reply),
				"count": 0,
			})
			return
		}
	}

	JsonResponse(w, map[string]interface{}{
		"transactions": transactions,
		"count":        len(transactions),
	})
}

package handlers

import (
	"bytes"
	"encoding/hex"
	"net/http"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	clientrpc "github.com/wonabru/qwid-node/rpc/client"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

type StakingDetail struct {
	DelegatedAddress string  `json:"delegatedAddress"`
	Staked           float64 `json:"staked"`
	Rewards          float64 `json:"rewards"`
}

func GetAccount(w http.ResponseWriter, r *http.Request) {
	addrStr := r.URL.Query().Get("address")
	if addrStr == "" {
		jsonError(w, "address parameter required", http.StatusBadRequest)
		return
	}

	addrBytes, err := hex.DecodeString(addrStr)
	if err != nil || len(addrBytes) != common.AddressLength {
		jsonError(w, "Invalid address format (expected 40 hex characters)", http.StatusBadRequest)
		return
	}

	// Fetch account via DETS
	reply := clientrpc.Call(SignMessage(append([]byte("DETS"), addrBytes...)))
	if bytes.Equal(reply, []byte("Timeout")) {
		jsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	if len(reply) < 3 || string(reply[:2]) != "AC" {
		jsonError(w, "Account not found", http.StatusNotFound)
		return
	}

	var acc account.Account
	if err := acc.Unmarshal(reply[2:]); err != nil {
		jsonError(w, "Failed to parse account", http.StatusInternalServerError)
		return
	}

	// Fetch staking info
	stake := 0.0
	rewards := 0.0
	locks := 0.0
	stakingDetails := []StakingDetail{}

	for i := 1; i < 5; i++ {
		inb := append([]byte("STAK"), addrBytes...)
		inb = append(inb, byte(i))
		re := clientrpc.Call(SignMessage(inb))
		if bytes.Equal(re, []byte("Timeout")) {
			continue
		}

		var stakeAcc account.StakingAccount
		if err := stakeAcc.Unmarshal(re[:len(re)-8]); err != nil {
			continue
		}

		stakedAmount := account.Int64toFloat64(stakeAcc.StakedBalance)
		rewardsAmount := account.Int64toFloat64(stakeAcc.StakingRewards)
		lockedAmount := account.Int64toFloat64(common.GetInt64FromByte(re[len(re)-8:]))

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

	// Fetch recent transactions (last 20 sent + 20 received)
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
						"timestamp": tx.TxParam.SendingTime,
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
						"type":      "received",
						"hash":      tx.Hash.GetHex(),
						"sender":    tx.TxParam.Sender.GetHex(),
						"amount":    account.Int64toFloat64(tx.TxData.Amount),
						"height":    tx.Height,
						"timestamp": tx.TxParam.SendingTime,
					})
				}
			}
		}
	}

	addr := common.Address{}
	addr.Init(acc.Address[:])

	jsonResponse(w, map[string]interface{}{
		"address":         addr.GetHex(),
		"balance":         acc.GetBalanceConfirmedFloat(),
		"stakedAmount":    stake,
		"lockedAmount":    locks,
		"rewardsAmount":   rewards,
		"totalHoldings":   acc.GetBalanceConfirmedFloat() + stake + rewards,
		"stakingDetails":  stakingDetails,
		"escrowDelay":     acc.TransactionDelay,
		"multiSignNumber": acc.MultiSignNumber,
		"sentCount":       acc.SentCount,
		"receivedCount":   acc.ReceivedCount,
		"transactions":    transactions,
	})
}

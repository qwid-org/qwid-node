package handlers

import (
	"bytes"
	"encoding/hex"
	"net/http"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func txToJSON(tx transactionsDefinition.Transaction, location string) map[string]interface{} {
	resp := map[string]interface{}{
		"hash":      tx.Hash.GetHex(),
		"sender":    tx.TxParam.Sender.GetHex(),
		"recipient": tx.TxData.Recipient.GetHex(),
		"amount":    account.Int64toFloat64(tx.TxData.Amount),
		"height":    tx.Height,
		"gasPrice":  tx.GasPrice,
		"gasUsage":  tx.GasUsage,
		"timestamp": tx.TxParam.SendingTime,
		"nonce":     tx.TxParam.Nonce,
		"chainId":   tx.TxParam.ChainID,
		"location":  location,
	}

	if len(tx.TxData.OptData) > 0 {
		resp["optData"] = hex.EncodeToString(tx.TxData.OptData)
	}
	if tx.TxData.LockedAmount != 0 {
		resp["lockedAmount"] = account.Int64toFloat64(tx.TxData.LockedAmount)
		resp["releasePerBlock"] = account.Int64toFloat64(tx.TxData.ReleasePerBlock)
		resp["delegatedAccountForLocking"] = tx.TxData.DelegatedAccountForLocking.GetHex()
	}
	if tx.TxData.EscrowTransactionsDelay != 0 {
		resp["escrowDelay"] = tx.TxData.EscrowTransactionsDelay
	}
	if tx.TxData.MultiSignNumber > 0 {
		resp["multiSignNumber"] = tx.TxData.MultiSignNumber
	}
	emptyAddr := common.EmptyAddress()
	if !bytes.Equal(tx.ContractAddress.GetBytes(), emptyAddr.GetBytes()) {
		resp["contractAddress"] = tx.ContractAddress.GetHex()
	}

	return resp
}

func GetTransaction(w http.ResponseWriter, r *http.Request) {
	hashStr := r.URL.Query().Get("hash")
	if hashStr == "" {
		jsonError(w, "hash parameter required", http.StatusBadRequest)
		return
	}

	b, err := hex.DecodeString(hashStr)
	if err != nil || len(b) != common.HashLength {
		jsonError(w, "Invalid hash format (expected 64 hex characters)", http.StatusBadRequest)
		return
	}

	reply := clientrpc.Call(SignMessage(append([]byte("DETS"), b...)))
	if bytes.Equal(reply, []byte("Timeout")) {
		jsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	if len(reply) < 3 || string(reply[:2]) != "TX" {
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
	tx, _, err = tx.GetFromBytes(reply[3+locLen:])
	if err != nil {
		jsonError(w, "Failed to parse transaction", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, txToJSON(tx, location))
}

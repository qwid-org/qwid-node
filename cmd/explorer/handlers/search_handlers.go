package handlers

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"regexp"
	"strconv"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	clientrpc "github.com/wonabru/qwid-node/rpc/client"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

var hexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		jsonError(w, "q parameter required", http.StatusBadRequest)
		return
	}

	// Try as block height (numeric)
	if height, err := strconv.ParseInt(q, 10, 64); err == nil {
		b := common.GetByteInt64(height)
		reply := clientrpc.Call(SignMessage(append([]byte("DETS"), b...)))
		if !bytes.Equal(reply, []byte("Timeout")) && len(reply) > 2 && string(reply[:2]) == "BL" {
			bb := blocks.Block{}
			bb, err = bb.GetFromBytes(reply[2:])
			if err == nil {
				jsonResponse(w, map[string]interface{}{
					"type":   "block",
					"result": blockToJSON(bb),
				})
				return
			}
		}
	}

	// Try as hex
	if hexPattern.MatchString(q) {
		b, err := hex.DecodeString(q)
		if err == nil {
			switch len(b) {
			case common.AddressLength:
				// Account lookup
				reply := clientrpc.Call(SignMessage(append([]byte("DETS"), b...)))
				if !bytes.Equal(reply, []byte("Timeout")) && len(reply) > 2 && string(reply[:2]) == "AC" {
					var acc account.Account
					if err := acc.Unmarshal(reply[2:]); err == nil {
						addr := common.Address{}
						addr.Init(acc.Address[:])
						jsonResponse(w, map[string]interface{}{
							"type": "account",
							"result": map[string]interface{}{
								"address": addr.GetHex(),
								"balance": acc.GetBalanceConfirmedFloat(),
							},
						})
						return
					}
				}
			case common.HashLength:
				// Transaction lookup
				reply := clientrpc.Call(SignMessage(append([]byte("DETS"), b...)))
				if !bytes.Equal(reply, []byte("Timeout")) && len(reply) > 2 {
					if string(reply[:2]) == "TX" && len(reply) > 3 {
						locLen := int(reply[2])
						if len(reply) > 3+locLen {
							location := string(reply[3 : 3+locLen])
							tx := transactionsDefinition.Transaction{}
							tx, _, err := tx.GetFromBytes(reply[3+locLen:])
							if err == nil {
								jsonResponse(w, map[string]interface{}{
									"type":   "transaction",
									"result": txToJSON(tx, location),
								})
								return
							}
						}
					}
				}
			}
		}
	}

	jsonError(w, "Not found", http.StatusNotFound)
}

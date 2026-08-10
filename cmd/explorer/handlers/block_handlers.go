package handlers

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"strconv"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/statistics"
)

func blockToJSON(bb blocks.Block) map[string]interface{} {
	txHashes := []string{}
	for _, h := range bb.TransactionsHashes {
		txHashes = append(txHashes, h.GetHex())
	}

	delegated := common.Address{}
	delegated.Init(bb.BaseBlock.BaseHeader.DelegatedAccount.GetBytes())
	operator := common.Address{}
	operator.Init(bb.BaseBlock.BaseHeader.OperatorAccount.GetBytes())

	return map[string]interface{}{
		"height":           bb.BaseBlock.BaseHeader.Height,
		"hash":             bb.BlockHash.GetHex(),
		"previousHash":     bb.BaseBlock.BaseHeader.PreviousHash.GetHex(),
		"difficulty":       bb.BaseBlock.BaseHeader.Difficulty,
		"timestamp":        bb.BaseBlock.BlockTimeStamp,
		"delegatedAccount": delegated.GetHex(),
		"operatorAccount":  operator.GetHex(),
		"merkleRoot":       bb.BaseBlock.BaseHeader.RootMerkleTree.GetHex(),
		"rewardPercentage": bb.BaseBlock.RewardPercentage,
		"supply":           account.Int64toFloat64(bb.BaseBlock.Supply),
		"priceOracle":      account.Int64toFloat64(bb.BaseBlock.PriceOracle),
		"randOracle":       bb.BaseBlock.RandOracle,
		"blockFee":         account.Int64toFloat64(bb.BlockFee),
		"txCount":          len(bb.TransactionsHashes),
		"txHashes":         txHashes,
	}
}

func GetBlock(w http.ResponseWriter, r *http.Request) {
	heightStr := r.URL.Query().Get("height")
	if heightStr == "" {
		jsonError(w, "height parameter required", http.StatusBadRequest)
		return
	}

	height, err := strconv.ParseInt(heightStr, 10, 64)
	if err != nil {
		jsonError(w, "Invalid height format", http.StatusBadRequest)
		return
	}

	b := common.GetByteInt64(height)
	reply := clientrpc.Call(SignMessage(append([]byte("DETS"), b...)))
	if bytes.Equal(reply, []byte("Timeout")) {
		jsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	if len(reply) < 3 || string(reply[:2]) != "BL" {
		jsonError(w, "Block not found", http.StatusNotFound)
		return
	}

	bb := blocks.Block{}
	bb, err = bb.GetFromBytes(reply[2:])
	if err != nil {
		jsonError(w, "Failed to parse block", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, blockToJSON(bb))
}

func GetBlocks(w http.ResponseWriter, r *http.Request) {
	fromStr := r.URL.Query().Get("from")
	countStr := r.URL.Query().Get("count")

	count := 20
	if countStr != "" {
		c, err := strconv.Atoi(countStr)
		if err == nil && c > 0 && c <= 50 {
			count = c
		}
	}

	var fromHeight int64

	if fromStr != "" {
		f, err := strconv.ParseInt(fromStr, 10, 64)
		if err != nil {
			jsonError(w, "Invalid from parameter", http.StatusBadRequest)
			return
		}
		fromHeight = f
	} else {
		// Get current height from stats
		reply := clientrpc.Call(SignMessage([]byte("STAT")))
		if bytes.Equal(reply, []byte("Timeout")) {
			jsonError(w, "Timeout", http.StatusGatewayTimeout)
			return
		}
		sm := statistics.GetStatsManager()
		st := sm.Stats
		if err := common.Unmarshal(reply, common.StatDBPrefix, &st); err != nil {
			jsonError(w, "Failed to get stats", http.StatusInternalServerError)
			return
		}
		fromHeight = st.Height
	}

	blockList := []map[string]interface{}{}

	for i := 0; i < count && fromHeight-int64(i) >= 0; i++ {
		h := fromHeight - int64(i)
		b := common.GetByteInt64(h)
		reply := clientrpc.Call(SignMessage(append([]byte("DETS"), b...)))
		if bytes.Equal(reply, []byte("Timeout")) {
			continue
		}
		if len(reply) < 3 || string(reply[:2]) != "BL" {
			continue
		}

		bb := blocks.Block{}
		bb, err := bb.GetFromBytes(reply[2:])
		if err != nil {
			continue
		}

		blockList = append(blockList, map[string]interface{}{
			"height":    bb.BaseBlock.BaseHeader.Height,
			"hash":      bb.BlockHash.GetHex(),
			"timestamp": bb.BaseBlock.BlockTimeStamp,
			"txCount":   len(bb.TransactionsHashes),
			"blockFee":  account.Int64toFloat64(bb.BlockFee),
		})
	}

	jsonResponse(w, map[string]interface{}{
		"blocks":     blockList,
		"fromHeight": fromHeight,
		"count":      len(blockList),
	})
}

func fetchBlockByHash(hashHex string) (blocks.Block, error) {
	b, err := hex.DecodeString(hashHex)
	if err != nil {
		return blocks.Block{}, err
	}
	reply := clientrpc.Call(SignMessage(append([]byte("DETS"), b...)))
	if len(reply) < 3 || string(reply[:2]) != "BL" {
		return blocks.Block{}, err
	}
	bb := blocks.Block{}
	bb, err = bb.GetFromBytes(reply[2:])
	return bb, err
}

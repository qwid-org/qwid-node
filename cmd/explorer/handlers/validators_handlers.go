package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/statistics"
)

type ValidatorInfo struct {
	ID               int     `json:"id"`
	DelegatedAddress string  `json:"delegatedAddress"`
	OperatorAddress  string  `json:"operatorAddress"`
	TotalStaked      float64 `json:"totalStaked"`
	StakerCount      int     `json:"stakerCount"`
	IsOperational    bool    `json:"isOperational"`
}

type ValidatorsResponse struct {
	TotalStaked float64         `json:"totalStaked"`
	Validators  []ValidatorInfo `json:"validators"`
}

func GetValidators(w http.ResponseWriter, r *http.Request) {
	reply := clientrpc.Call(SignMessage([]byte("VALS")))
	if bytes.Equal(reply, []byte("Timeout")) {
		jsonError(w, "Timeout", http.StatusGatewayTimeout)
		return
	}

	var resp ValidatorsResponse
	if err := json.Unmarshal(reply, &resp); err != nil {
		jsonError(w, "Failed to parse validators data", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, resp)
}

type BlockProducerStats struct {
	OperatorAddress string `json:"operatorAddress"`
	BlocksProduced  int    `json:"blocksProduced"`
	LastBlockHeight int64  `json:"lastBlockHeight"`
	LastBlockTime   int64  `json:"lastBlockTime"`
}

// maxValidatorBlocks bounds the full-block reads one request can order
// (S8-02); the explorer page asks for 10.
const maxValidatorBlocks = 50

func validatorBlocksCount(r *http.Request) int {
	if c, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && c > 0 && c <= maxValidatorBlocks {
		return c
	}
	return 10
}

func GetValidatorBlocks(w http.ResponseWriter, r *http.Request) {
	count := validatorBlocksCount(r)

	// Get current height
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
	currentHeight := st.Height

	producerMap := map[string]*BlockProducerStats{}
	var latestSupply float64

	for i := 0; i < count && currentHeight-int64(i) >= 0; i++ {
		h := currentHeight - int64(i)
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

		if i == 0 {
			latestSupply = account.Int64toFloat64(bb.BaseBlock.Supply)
		}

		operator := common.Address{}
		operator.Init(bb.BaseBlock.BaseHeader.OperatorAccount.GetBytes())
		opHex := operator.GetHex()

		if _, ok := producerMap[opHex]; !ok {
			producerMap[opHex] = &BlockProducerStats{
				OperatorAddress: opHex,
			}
		}
		ps := producerMap[opHex]
		ps.BlocksProduced++
		if ps.LastBlockHeight == 0 || h > ps.LastBlockHeight {
			ps.LastBlockHeight = h
			ps.LastBlockTime = bb.BaseBlock.BlockTimeStamp
		}
	}

	producers := []BlockProducerStats{}
	for _, ps := range producerMap {
		producers = append(producers, *ps)
	}

	jsonResponse(w, map[string]interface{}{
		"producers":     producers,
		"blocksScanned": count,
		"currentHeight": currentHeight,
		"supply":        latestSupply,
	})
}

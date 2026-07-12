package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	clientrpc "github.com/wonabru/qwid-node/rpc/client"
	"github.com/wonabru/qwid-node/statistics"
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
	Supply              float64 `json:"supply"`
	TotalStaked         float64 `json:"totalStaked"`
	ActiveValidators    int     `json:"activeValidators"`
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
	}

	// Get supply from latest block
	b := common.GetByteInt64(st.Height)
	blockReply := clientrpc.Call(SignMessage(append([]byte("DETS"), b...)))
	if !bytes.Equal(blockReply, []byte("Timeout")) && len(blockReply) > 2 && string(blockReply[:2]) == "BL" {
		bb := blocks.Block{}
		bb, err = bb.GetFromBytes(blockReply[2:])
		if err == nil {
			resp.Supply = account.Int64toFloat64(bb.BaseBlock.Supply)
		}
	}

	// Get total staked from VALS
	valsReply := clientrpc.Call(SignMessage([]byte("VALS")))
	if !bytes.Equal(valsReply, []byte("Timeout")) {
		var valsResp ValidatorsResponse
		if err := json.Unmarshal(valsReply, &valsResp); err == nil {
			resp.TotalStaked = valsResp.TotalStaked
			resp.ActiveValidators = len(valsResp.Validators)
		}
	}

	jsonResponse(w, resp)
}

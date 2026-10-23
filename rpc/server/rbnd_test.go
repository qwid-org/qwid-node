package serverrpc

import (
	"encoding/json"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// RBND lets a wallet see whether its recovery bind is on chain and from which
// height, so it can tell the owner when the reveal becomes possible.
func TestRBNDReportsABind(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccountsRPC()
	key := [32]byte{7}
	account.AddRecoveryBind(key, account.RecoveryBind{Identity: rpcAddress(1).ByteValue, Height: 120})
	t.Cleanup(func() { account.DeleteRecoveryBind(key) })

	var reply []byte
	handleRBND(key[:], &reply)
	var got struct {
		Exists  bool  `json:"exists"`
		Height  int64 `json:"height"`
		ReadyAt int64 `json:"readyAt"`
	}
	if err := json.Unmarshal(reply, &got); err != nil {
		t.Fatalf("%v: %s", err, reply)
	}
	if !got.Exists || got.Height != 120 || got.ReadyAt != 120+common.RecoveryBindDelayBlocks {
		t.Fatalf("got %+v", got)
	}
	handleRBND(make([]byte, 32), &reply)
	if err := json.Unmarshal(reply, &got); err != nil || got.Exists {
		t.Fatalf("an absent bind was reported: %s", reply)
	}
}

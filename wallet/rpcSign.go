package wallet

import (
	"bytes"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// SignRPCRequest frames line (operation || payload) for the node's RPC and,
// for an operation that needs it, signs it with w under the live scheme
// together with a replay guard (common.NewRPCGuard, S7-07). It is the one
// implementation behind every client's SignMessage.
func SignRPCRequest(w *Wallet, line []byte) []byte {
	if len(line) < 4 {
		return common.BytesToLenAndBytes(line)
	}
	for _, op := range common.ConnectionsWithoutVerification {
		if bytes.Equal(line[:4], op) {
			return common.BytesToLenAndBytes(line)
		}
	}
	if w == nil || !w.Check() || !w.Check2() {
		logger.GetLogger().Println("wallet not loaded yet")
		return line
	}
	msg := append(common.BytesToLenAndBytes(line), common.NewRPCGuard()...)
	sign, err := w.Sign(msg, !common.IsPaused())
	if err != nil {
		logger.GetLogger().Println(err)
		return msg
	}
	return append(msg, sign.GetBytes()...)
}

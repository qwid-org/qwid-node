package transactionsDefinition

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
)

func TestCancellationOptDataRoundTrip(t *testing.T) {
	var target common.Hash
	targetBytes := make([]byte, common.HashLength)
	for i := range targetBytes {
		targetBytes[i] = byte(i + 1)
	}
	target.Set(targetBytes)
	tx := Transaction{TxData: TxData{OptData: CancellationOptData(target)}}

	got, ok := tx.CancellationTarget()
	if !ok || got != target {
		t.Fatalf("cancellation target round-trip failed: ok=%v got=%x want=%x", ok, got.GetBytes(), target.GetBytes())
	}
	tx.TxData.OptData = tx.TxData.OptData[:len(tx.TxData.OptData)-1]
	if _, ok := tx.CancellationTarget(); ok {
		t.Fatal("truncated cancellation payload accepted")
	}
}

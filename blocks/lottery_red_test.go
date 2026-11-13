package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Proof-of-synergy redesign (audit 2026-11-12 F-CONS-01): the lottery must not
// depend on anything the producer can choose - above all not on the header
// signature, which Falcon produces afresh, and validly, on every signing.

func TestHeaderHashDoesNotDependOnTheSignature(t *testing.T) {
	k, parent := headerTestSetup(t)
	bl := signedTestBlock(t, k, 10, parent, common.Hash{})
	again := resealTestBlock(t, k, bl) // same content, signed once more
	if bl.BaseBlock.BaseHeader.Signature.GetHex() == again.BaseBlock.BaseHeader.Signature.GetHex() {
		t.Skip("the scheme produced the same signature twice; cannot tell")
	}
	if bl.BaseBlock.BlockHeaderHash != again.BaseBlock.BlockHeaderHash {
		t.Fatal("re-signing the same header changes BlockHeaderHash: every signature is a fresh lottery ticket")
	}
	if bl.BlockHash != again.BlockHash {
		t.Fatal("re-signing the same block changes its identity")
	}
}

// A block stamped beyond the clock tolerance is invalid on every path, sync
// included (it used to be accepted there up to MaxBlockTimeInterval ahead).
func TestFutureTimestampIsRefusedWhileSyncing(t *testing.T) {
	now := common.GetCurrentTimeStampInSecond()
	parent := timestampBlock(100, now-20)
	if err := validateBlockTimestamp(timestampBlock(101, now+common.MaxBlockForwardInTime+5), parent, false); err == nil {
		t.Fatal("the sync path accepted a block stamped beyond the clock tolerance")
	}
	if err := validateBlockTimestamp(timestampBlock(101, now+common.MaxBlockForwardInTime), parent, false); err != nil {
		t.Fatalf("a block within the tolerance was refused: %v", err)
	}
}

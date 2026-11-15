package services

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/tcpip"
)

// A produced block travels on the nonce topic (BroadcastBlock). Its cap
// counted only the transaction hashes; the embedded oracle proofs - up to one
// dual-signed nonce per delegated account - did not fit, and every peer would
// drop a full block as over-long (audit 2026-11-15).
func fullBlock(proofSize int) blocks.Block {
	var bl blocks.Block
	bl.TransactionsHashes = make([]common.Hash, common.MaxTransactionsPerBlock)
	for i := range bl.TransactionsHashes {
		bl.TransactionsHashes[i][0] = byte(i)
		bl.TransactionsHashes[i][1] = byte(i >> 8)
	}
	for i := 0; i < int(blocks.MaxOracleProofs); i++ {
		bl.BaseBlock.OracleProofs = append(bl.BaseBlock.OracleProofs, bytes.Repeat([]byte{byte(i)}, proofSize))
	}
	return bl
}

func TestFullBlockWithDualSignedProofsFitsTheNonceTopic(t *testing.T) {
	// A dual-signed nonce with MAYO-5 on both slots: ~2.3 KB; take 3 KB.
	bl := fullBlock(3 << 10)
	n := len(GenerateBlockMessage(bl).GetBytes())
	if limit := int(tcpip.MaxMessageSizeForTopic(tcpip.NonceTopic)); n > limit {
		t.Fatalf("a full block message is %d bytes, the nonce topic accepts %d", n, limit)
	}
}

// Proofs of larger schemes are cut to the budget by the producer, so a block
// it produces always fits the topic.
func TestProducerKeepsProofsWithinTheBroadcastBudget(t *testing.T) {
	bl := fullBlock(64 << 10)
	bl.BaseBlock.OracleProofs = blocks.FitOracleProofs(bl.BaseBlock.OracleProofs)
	if len(bl.BaseBlock.OracleProofs) == 0 {
		t.Fatal("no proof kept")
	}
	n := len(GenerateBlockMessage(bl).GetBytes())
	if limit := int(tcpip.MaxMessageSizeForTopic(tcpip.NonceTopic)); n > limit {
		t.Fatalf("a block with trimmed proofs is %d bytes, the nonce topic accepts %d", n, limit)
	}
}

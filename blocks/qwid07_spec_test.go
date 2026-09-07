package blocks

// QWID-2026-07: the block-producer header signature must be authenticated
// BEFORE any expensive or persistent work. A block with an invalid header
// signature must be rejected at that check — not after stake verification,
// transaction processing, EVM execution, or persistent public-key writes.

import (
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/logger"
)

func TestQWID07_HeaderVerifiedBeforeExpensiveWork(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withBalanceTestDB(t)
	initTestAccounts()
	initTestStaking()

	// buildMinimalBlock carries a garbage header signature (SignatureMessage
	// does not match the header bytes), so verifyBlockHeaderSignature fails.
	newBlock := buildMinimalBlock()
	newBlock.BaseBlock.BaseHeader.Height = 42
	lastBlock := buildMinimalBlock()
	lastBlock.BaseBlock.BaseHeader.Height = 41

	// merkleTrie is nil: with the fix the header check fails first and returns
	// before any path that would use the tree.
	err := CheckBlockAndTransactions(&newBlock, lastBlock, nil, false)
	if err == nil {
		t.Fatal("a block with an invalid header signature was accepted (QWID-2026-07)")
	}
	// The failure must be the header authentication, proving it runs before the
	// stake/transaction/EVM work (those would otherwise fail first and mask it).
	msg := err.Error()
	if strings.Contains(msg, "top-128") || strings.Contains(msg, "staking") ||
		strings.Contains(msg, "transaction") || strings.Contains(msg, "delegated") {
		t.Fatalf("the header signature is verified too late — an expensive check failed first: %v (QWID-2026-07)", err)
	}
}


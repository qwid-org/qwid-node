package transactionsPool

// Executable specification for the open audit findings that live in this
// package (SECURITY_AUDIT_2026-09-05.md). Each test asserts the DESIRED
// behaviour: where the finding is still unfixed the test FAILS, documenting the
// hole; once a fix lands it must pass unchanged. Test names carry the finding
// ID so the remaining work is visible in every test run.

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// specTx builds a decodable transaction with a synthetic full-length signature.
func specTx(marker byte, gasPrice int64) transactionsDefinition.Transaction {
	sigBytes := make([]byte, common.SignatureLength(false)+1)
	sig, _ := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{
			ChainID:     common.GetChainID(),
			Sender:      common.EmptyAddress(),
			SendingTime: int64(marker),
			Nonce:       int64(marker),
		},
		TxData: transactionsDefinition.TxData{
			Recipient: common.EmptyAddress(),
			Amount:    1,
			OptData:   []byte{marker},
		},
		Height:    5,
		GasPrice:  gasPrice,
		GasUsage:  1,
		Signature: sig,
	}
	_ = tx.CalcHashAndSet()
	return tx
}

// QWID-2026-19: a transaction that sits in the confirmed DB was included at
// some height >= its sender-declared composition height. The duplicate check
// must reject it REGARDLESS of which height the committed-hash list records it
// at — searching only the declared height is exactly the bug that makes
// confirmed-transaction replay possible.
func TestQWID19_ConfirmedTxIsDuplicateRegardlessOfDeclaredHeight(t *testing.T) {
	logger.InitLogger()
	cleanup := withInMemoryDB(t)
	defer cleanup()
	InitPermanentTrie()

	tx := specTx(19, 1)
	// Sender declared height 5; the chain committed it at height 8.
	tx.Height = 5
	_ = tx.CalcHashAndSet()
	hash := tx.GetHash().GetBytes()
	if err := tx.StoreToDBPoolTx(common.TransactionDBPrefix[:]); err != nil {
		t.Fatalf("cannot store confirmed tx: %v", err)
	}
	// The block that committed it did so at height 8 (not the declared 5).
	MarkTxIncluded(hash, 8)

	// A later block being validated must detect the duplicate regardless of the
	// transaction's declared height. Any tree is fine; the answer no longer
	// depends on it.
	currentTree, _ := BuildMerkleTree(9, [][]byte{}, database.MainDB)
	if err := CheckTransactionInDBAndInMarkleTrie(hash, currentTree); err == nil {
		t.Fatal("a transaction already committed on the chain was NOT reported as a duplicate — " +
			"a producer can re-include it and every validator will re-execute the transfer (QWID-2026-19)")
	}

	// After the committing block is rewound, the transaction must become
	// re-appliable (not wrongly rejected forever).
	UnmarkTxIncluded(hash)
	if err := CheckTransactionInDBAndInMarkleTrie(hash, currentTree); err != nil {
		t.Fatalf("a reverted transaction was still rejected as a duplicate after rewind: %v (QWID-2026-19)", err)
	}
}

// QWID-2026-20: when the pool overflows, the entry that gets evicted must be
// the WORST one, never the best. The max-heap Pop currently removes the
// highest-priority transaction — the same one block inclusion would serve
// first — which hands an attacker free censorship of all paying traffic.
func TestQWID20_OverflowEvictsWorstNotBest(t *testing.T) {
	logger.InitLogger()
	pool := NewTransactionPool(3, 0) // typePool 0: priority = gas price

	best := specTx(1, 30)
	mid := specTx(2, 20)
	low := specTx(3, 10)
	junk := specTx(4, 1)
	for _, tx := range []transactionsDefinition.Transaction{best, mid, low} {
		if !pool.AddTransaction(tx, tx.GetHash()) {
			t.Fatalf("setup add failed")
		}
	}
	pool.AddTransaction(junk, junk.GetHash()) // overflow: someone must go

	if !pool.HasTransaction(best.GetHash().GetBytes()) {
		t.Fatal("overflow evicted the HIGHEST-priority transaction — " +
			"filling the pool with minimum-fee junk censors all paying traffic (QWID-2026-20)")
	}
}

// QWID-2026-21: membership on an empty tree must be false, not an
// index-out-of-range panic — the panic is reachable inside block application
// through a failing escrow settlement on an empty block.
func TestQWID21_EmptyTreeMembershipDoesNotPanic(t *testing.T) {
	tree := &MerkleTree{}
	var hash [common.HashLength]byte
	hash[0] = 0x21

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("IsTxHashInTree on an empty tree panicked (%v) — this panic fires inside "+
				"block application on every node when a matured escrow fails in an empty block (QWID-2026-21)", r)
		}
	}()
	if tree.IsTxHashInTree(hash[:]) {
		t.Fatal("empty tree claims membership")
	}
}

// QWID-2026-22: banning a transaction enough times must eventually make the
// pool refuse it. Today the counter is deleted at 51 while refusal needs 101,
// so every ban — including an owner's CNCL cancellation — is a no-op.
func TestQWID22_RepeatedBansEventuallyRefuseAdmission(t *testing.T) {
	logger.InitLogger()
	pool := NewTransactionPool(10, 0)
	tx := specTx(22, 5)
	hash := tx.GetHash().GetBytes()

	for i := 0; i < 300; i++ {
		pool.BanTransactionByHash(hash)
	}
	if pool.AddTransaction(tx, tx.GetHash()) {
		t.Fatal("a transaction banned 300 times was admitted anyway — the ban thresholds " +
			"make every ban (including owner cancellation via CNCL) a no-op (QWID-2026-22)")
	}
}

// QWID-2026-23: a tree built from a block's transaction hashes must answer
// membership for exactly those hashes. The check currently compares raw
// hashes against hashed node data and can never return true — which both
// disables the QWID-19 fallback and hides the nil-padded leaf construction.
func TestQWID23_TreeMembershipMatchesItsOwnLeaves(t *testing.T) {
	logger.InitLogger()
	cleanup := withInMemoryDB(t)
	defer cleanup()

	h1 := bytes.Repeat([]byte{0xA1}, common.HashLength)
	h2 := bytes.Repeat([]byte{0xB2}, common.HashLength)
	other := bytes.Repeat([]byte{0xC3}, common.HashLength)

	tree, err := BuildMerkleTree(4, [][]byte{h1, h2}, database.MainDB)
	if err != nil {
		t.Fatalf("cannot build tree: %v", err)
	}
	if !tree.IsTxHashInTree(h1) || !tree.IsTxHashInTree(h2) {
		t.Fatal("a tree built from two hashes denies containing them — the membership check is " +
			"structurally dead, disabling the duplicate-check fallback (QWID-2026-23)")
	}
	if tree.IsTxHashInTree(other) {
		t.Fatal("tree claims membership of a hash it was not built from")
	}
}

// QWID-2026-36 (quarantine aspect): an escrow entry that fails reload
// verification is consensus-relevant pending state; it must be QUARANTINED,
// never hard-deleted. After a voted scheme replacement the old entries fail
// verification on every restarted node — deleting them is what turns a scheme
// change plus a restart into a silent, permanent balance divergence.
func TestQWID36_FailedReloadVerificationDoesNotDeleteTheEntry(t *testing.T) {
	logger.InitLogger()
	cleanup := withInMemoryDB(t)
	defer cleanup()

	PoolTxEscrow = NewTransactionPool(common.MaxTransactionInPool, 1)
	saved := verifyPersistedEscrow
	verifyPersistedEscrow = func(*transactionsDefinition.Transaction) bool { return true }
	tx := buildEscrowTx(36)
	hash := tx.GetHash().GetBytes()
	if !AddEscrowTransaction(tx) {
		t.Fatal("setup: cannot add escrow tx")
	}
	verifyPersistedEscrow = saved
	t.Cleanup(func() { verifyPersistedEscrow = saved })

	// Simulate the post-scheme-change restart: fresh pool, verification fails.
	PoolTxEscrow = NewTransactionPool(common.MaxTransactionInPool, 1)
	verifyPersistedEscrow = func(*transactionsDefinition.Transaction) bool { return false }
	_ = LoadEscrowPoolFromDB()

	key := append(append([]byte{}, common.EscrowPoolDBPrefix[:]...), hash...)
	ok, err := database.MainDB.IsKey(key)
	if err != nil {
		t.Fatalf("IsKey failed: %v", err)
	}
	if !ok {
		t.Fatal("an escrow entry that failed reload verification was permanently DELETED — " +
			"after a scheme replacement every restarted node erases settlements that running " +
			"nodes will still perform (QWID-2026-36)")
	}
}

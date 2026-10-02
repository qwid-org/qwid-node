package syncServices

import (
	"bytes"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

type forkVerdict int

const (
	// forkInvalid: the competing block proves nothing - wrong height, wrong
	// hash or no valid producer signature. Never rewind for it.
	forkInvalid forkVerdict = iota
	// forkVerified: an authentic block that links to our own block index-1;
	// the chains share that ancestor and diverge at index.
	forkVerified
	// forkDeeper: an authentic block whose parent is not ours - the fork point
	// lies further back and needs earlier headers to locate.
	forkDeeper
)

// verifyCompetingBlock judges a peer's block that differs from ours at index
// (S2-01). Rewinding deletes blocks, so only a block a real producer signed,
// hashed as declared, may move the chain back - and only to the ancestor it
// demonstrably shares with us.
//
// The header signature is checked under the scheme configuration of our own
// block index-1, the same rule verifyBlockHeaderSignature applies when a block
// is applied: a block is signed under the rules in force before it.
func verifyCompetingBlock(block blocks.Block, index int64) forkVerdict {
	if index < 1 || block.GetHeader().Height != index {
		return forkInvalid
	}
	hash, err := block.CalcBlockHash()
	if err != nil || !bytes.Equal(hash.GetBytes(), block.BlockHash.GetBytes()) {
		return forkInvalid
	}
	parent, err := blocks.LoadBlock(index - 1)
	if err != nil {
		logger.GetLogger().Println("cannot load our block", index-1, "to judge a competing block:", err)
		return forkInvalid
	}
	sigName, sigName2, isPaused, isPaused2, err := parent.GetSigNames()
	if err != nil {
		return forkInvalid
	}
	header := block.GetHeader()
	if len(header.Signature.GetBytes()) == 0 || !header.Verify(sigName, sigName2, isPaused, isPaused2) {
		return forkInvalid
	}
	if !bytes.Equal(header.PreviousHash.GetBytes(), parent.BlockHash.GetBytes()) {
		return forkDeeper
	}
	return forkVerified
}

// authenticBatchHeader reports whether a block of a sync batch, at index on
// top of parent, is authentic enough to act on before full verification
// (S2-05): its declared height and hash, its link to parent, a valid producer
// signature, and a transaction list matching the signed merkle root - the
// signature covers the root, not the list, so the list is checked separately.
// Only authentic headers may feed the missing-transaction requests.
func authenticBatchHeader(block blocks.Block, index int64, parent blocks.Block) bool {
	header := block.GetHeader()
	if header.Height != index || !bytes.Equal(header.PreviousHash.GetBytes(), parent.BlockHash.GetBytes()) {
		return false
	}
	hash, err := block.CalcBlockHash()
	if err != nil || !bytes.Equal(hash.GetBytes(), block.BlockHash.GetBytes()) {
		return false
	}
	if !bytes.Equal(merkleRoot(block.TransactionsHashes), header.RootMerkleTree.GetBytes()) {
		return false
	}
	sigName, sigName2, isPaused, isPaused2, err := parent.GetSigNames()
	if err != nil || len(header.Signature.GetBytes()) == 0 {
		return false
	}
	return header.Verify(sigName, sigName2, isPaused, isPaused2)
}

// merkleRoot computes the root CheckBaseBlock compares against, without a
// database: the same tree, and the empty hash for an empty list.
func merkleRoot(hashes []common.Hash) []byte {
	data := make([][]byte, 0, len(hashes))
	for _, h := range hashes {
		data = append(data, h.GetBytes())
	}
	nodes, err := transactionsPool.NewMerkleTree(data)
	if err != nil || len(nodes) == 0 {
		return common.EmptyHash().GetBytes()
	}
	return nodes[0].Data
}

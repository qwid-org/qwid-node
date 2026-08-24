package blocks

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
)

func encConfigBytes(t *testing.T, sigName string, pub, priv, sig int) []byte {
	t.Helper()
	b, err := oqs.GenerateBytesFromParams(sigName, pub, priv, sig, false)
	assert.NoError(t, err)
	return b
}

func blockWithEnc(height int64, enc1, enc2 []byte) Block {
	return Block{
		BaseBlock: BaseBlock{
			BaseHeader: BaseHeader{
				Height:      height,
				Encryption1: enc1,
				Encryption2: enc2,
			},
		},
	}
}

// A scheme change at newBlock's height: proofs signed at earlier heights must
// resolve to the configuration recorded in the chain at their own height, not
// to the containing block's (or the node's current) configuration.
func TestSigNamesAtProofHeightUsesConfigAtSigningHeight(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	saved := database.MainDB
	database.MainDB = pdb
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB = saved
	})

	falcon512 := encConfigBytes(t, "Falcon-512", 897, 1281, 752)
	mayo5 := encConfigBytes(t, "MAYO-5", 5554, 40, 964)
	falcon1024 := encConfigBytes(t, "Falcon-1024", 1793, 2305, 1462)

	lastBlock := blockWithEnc(99, falcon512, mayo5)      // old secondary scheme still in force
	newBlock := blockWithEnc(100, falcon512, falcon1024) // secondary scheme replaced here

	// Proof signed at the containing block's height -> the new configuration.
	_, s2, _, _, err := sigNamesAtProofHeight(100, newBlock, lastBlock)
	assert.NoError(t, err)
	assert.Equal(t, "Falcon-1024", s2)

	// Proof signed at the parent's height -> the old configuration.
	_, s2, _, _, err = sigNamesAtProofHeight(99, newBlock, lastBlock)
	assert.NoError(t, err)
	assert.Equal(t, "MAYO-5", s2)

	// Proof signed below the parent with the block stored in the DB -> that
	// block's configuration. The stored block deliberately differs from the
	// parent (primary Dilithium instead of Falcon-512), so this passes only if
	// the config really came from the DB and not from the fallback.
	dilithium := encConfigBytes(t, "Dilithium5", 2592, 4864, 4595)
	stored := blockWithEnc(97, dilithium, mayo5)
	// A block only round-trips through StoreBlock/LoadBlock with a non-empty
	// header signature.
	sig, err := common.GetSignatureFromBytes([]byte{0, 1, 2, 3}, stored.BaseBlock.BaseHeader.OperatorAccount)
	assert.NoError(t, err)
	stored.BaseBlock.BaseHeader.Signature = sig
	hash, err := stored.CalcBlockHash()
	assert.NoError(t, err)
	stored.BlockHash = hash
	assert.NoError(t, stored.StoreBlock())
	s1, s2, _, _, err := sigNamesAtProofHeight(97, newBlock, lastBlock)
	assert.NoError(t, err)
	assert.Equal(t, "Dilithium5", s1)
	assert.Equal(t, "MAYO-5", s2)

	// Height whose block is not loadable (same un-applied sync batch) -> the
	// parent's configuration as fallback.
	_, s2, _, _, err = sigNamesAtProofHeight(96, newBlock, lastBlock)
	assert.NoError(t, err)
	assert.Equal(t, "MAYO-5", s2)
}

// Pins the decision that re-verifying an already-embedded oracle proof does not
// apply the pause gate. Reintroducing it re-judges committed history by today's
// policy and halts the chain at the first block carrying a proof signed under a
// since-paused scheme — which is exactly how it failed once.
func TestHistoricalProofVerificationIgnoresPauseFlags(t *testing.T) {
	isPaused, isPaused2 := historicalProofPauseFlags()
	if isPaused || isPaused2 {
		t.Fatalf("historical proof verification applies the pause gate (%v, %v); a signature valid when it was made must stay valid",
			isPaused, isPaused2)
	}
}

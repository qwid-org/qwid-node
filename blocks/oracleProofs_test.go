package blocks

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

// oracleTriple builds the 17-byte on-block encoding of one oracle entry:
// 1-byte delegated id, 8-byte height, 8-byte value.
func oracleTriple(id uint8, height, value int64) []byte {
	b := []byte{id}
	b = append(b, common.GetByteInt64(height)...)
	b = append(b, common.GetByteInt64(value)...)
	return b
}

// nonceTxFor builds the in-memory oracle nonce transaction a validator would
// sign: recipient is the delegated account, amount zero, and OptData carries
// price and rand after the 8-byte height + 32-byte parent-hash prefix.
func nonceTxFor(id uint8, height, price, rand int64) *transactionsDefinition.Transaction {
	opt := make([]byte, 8+common.HashLength)
	opt = append(opt, common.GetByteInt64(price)...)
	opt = append(opt, common.GetByteInt64(rand)...)
	return &transactionsDefinition.Transaction{
		TxData: transactionsDefinition.TxData{
			Recipient: common.GetDelegatedAccountAddress(int16(id)),
			Amount:    0,
			OptData:   opt,
		},
		Height: height,
	}
}

func TestExtractOracleSubmission(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	tx := nonceTxFor(5, 42, 100000000, 777)
	id, sub, err := extractOracleSubmission(tx)
	assert.NoError(t, err)
	assert.Equal(t, uint8(5), id)
	assert.Equal(t, int64(42), sub.height)
	assert.Equal(t, int64(100000000), sub.price)
	assert.Equal(t, int64(777), sub.rand)
}

func TestExtractOracleSubmissionRejectsNonZeroAmount(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	tx := nonceTxFor(5, 42, 100000000, 777)
	tx.TxData.Amount = 1
	_, _, err := extractOracleSubmission(tx)
	assert.Error(t, err)
}

func TestMatchOracleDataAcceptsBackedTriples(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	subs := map[uint8]oracleSubmission{
		2: {height: 10, price: 100, rand: 500},
		5: {height: 12, price: 200, rand: 600},
	}
	priceData := append(oracleTriple(2, 10, 100), oracleTriple(5, 12, 200)...)
	randData := append(oracleTriple(2, 10, 500), oracleTriple(5, 12, 600)...)
	assert.NoError(t, matchOracleData(subs, priceData, randData))
}

func TestMatchOracleDataRejectsFabricatedValue(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	subs := map[uint8]oracleSubmission{
		2: {height: 10, price: 100, rand: 500},
	}
	// Producer declares price 999 for id 2 while the signed proof says 100.
	priceData := oracleTriple(2, 10, 999)
	randData := oracleTriple(2, 10, 500)
	assert.Error(t, matchOracleData(subs, priceData, randData))
}

func TestMatchOracleDataRejectsUnbackedID(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	subs := map[uint8]oracleSubmission{
		2: {height: 10, price: 100, rand: 500},
	}
	// id 7 has no signed proof.
	priceData := append(oracleTriple(2, 10, 100), oracleTriple(7, 10, 300)...)
	randData := oracleTriple(2, 10, 500)
	assert.Error(t, matchOracleData(subs, priceData, randData))
}

func TestMatchOracleDataRejectsRandMismatch(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	subs := map[uint8]oracleSubmission{
		2: {height: 10, price: 100, rand: 500},
	}
	priceData := oracleTriple(2, 10, 100)
	randData := oracleTriple(2, 10, 999) // proof says 500
	assert.Error(t, matchOracleData(subs, priceData, randData))
}

// decoderFor returns an injected decoder keyed by the first proof byte, so the
// signature/serialization path can be stubbed while the freshness, duplicate,
// and matching logic is exercised deterministically.
func decoderFor(txs map[byte]*transactionsDefinition.Transaction, failOn byte) verifiedDecoder {
	return func(pb []byte) (*transactionsDefinition.Transaction, error) {
		if len(pb) == 0 || pb[0] == failOn {
			return nil, fmt.Errorf("decode/verify failed")
		}
		tx, ok := txs[pb[0]]
		if !ok {
			return nil, fmt.Errorf("no tx for marker %d", pb[0])
		}
		return tx, nil
	}
}

func TestAuthenticateOracleProofsAcceptsFreshSignedProofs(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	txs := map[byte]*transactionsDefinition.Transaction{
		1: nonceTxFor(2, 10, 100, 500),
		2: nonceTxFor(5, 10, 200, 600),
	}
	proofs := [][]byte{{1}, {2}}
	priceData := append(oracleTriple(2, 10, 100), oracleTriple(5, 10, 200)...)
	randData := append(oracleTriple(2, 10, 500), oracleTriple(5, 10, 600)...)

	err := authenticateOracleProofs(12, proofs, priceData, randData, decoderFor(txs, 0xff))
	assert.NoError(t, err)
}

func TestAuthenticateOracleProofsRejectsStaleProof(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	txs := map[byte]*transactionsDefinition.Transaction{
		1: nonceTxFor(2, 1, 100, 500), // height 1, block far ahead → stale
	}
	proofs := [][]byte{{1}}
	priceData := oracleTriple(2, 1, 100)
	randData := oracleTriple(2, 1, 500)

	err := authenticateOracleProofs(1+common.OraclesHeightDistance+5, proofs, priceData, randData, decoderFor(txs, 0xff))
	assert.Error(t, err)
}

func TestAuthenticateOracleProofsRejectsDuplicateID(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	txs := map[byte]*transactionsDefinition.Transaction{
		1: nonceTxFor(2, 10, 100, 500),
		2: nonceTxFor(2, 10, 100, 500), // same delegated id 2
	}
	proofs := [][]byte{{1}, {2}}
	priceData := oracleTriple(2, 10, 100)
	randData := oracleTriple(2, 10, 500)

	err := authenticateOracleProofs(12, proofs, priceData, randData, decoderFor(txs, 0xff))
	assert.Error(t, err)
}

func TestAuthenticateOracleProofsPropagatesDecodeError(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	txs := map[byte]*transactionsDefinition.Transaction{}
	proofs := [][]byte{{0xff}} // decoder fails on 0xff
	err := authenticateOracleProofs(12, proofs, nil, nil, decoderFor(txs, 0xff))
	assert.Error(t, err)
}

func TestAuthorizeOracleProofSigners(t *testing.T) {
	txs := map[byte]*transactionsDefinition.Transaction{
		1: nonceTxFor(2, 10, 100, 500),
	}
	txs[1].TxParam.Sender = stakeOperator(7)

	t.Run("authorized operator passes", func(t *testing.T) {
		err := authorizeOracleProofSigners([][]byte{{1}}, decoderFor(txs, 0xff), func(id int, sender common.Address) bool {
			return id == 2 && sender == stakeOperator(7)
		})
		assert.NoError(t, err)
	})

	t.Run("signer of another delegated account is rejected", func(t *testing.T) {
		err := authorizeOracleProofSigners([][]byte{{1}}, decoderFor(txs, 0xff), func(id int, sender common.Address) bool {
			return false
		})
		assert.Error(t, err)
	})
}

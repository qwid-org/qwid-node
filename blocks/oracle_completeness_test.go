package blocks

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// S4-06: a producer may not embed a validator's proof and then leave that
// validator's values out of the aggregation. The oracle data must be exactly
// what the embedded proofs say.
func TestOracleDataMustCoverEveryEmbeddedProof(t *testing.T) {
	logger.InitLogger()
	txs := map[byte]*transactionsDefinition.Transaction{
		1: nonceTxFor(2, 10, 100, 500),
		2: nonceTxFor(5, 10, 200, 600),
	}
	proofs := [][]byte{{1}, {2}}
	full := append(oracleTriple(2, 10, 100), oracleTriple(5, 10, 200)...)
	fullRand := append(oracleTriple(2, 10, 500), oracleTriple(5, 10, 600)...)

	if err := authenticateOracleProofs(12, proofs, oracleTriple(2, 10, 100), fullRand, decoderFor(txs, 0xff)); err == nil {
		t.Fatal("a price left out for an embedded proof must be rejected")
	}
	if err := authenticateOracleProofs(12, proofs, full, oracleTriple(5, 10, 600), decoderFor(txs, 0xff)); err == nil {
		t.Fatal("a rand left out for an embedded proof must be rejected")
	}
	if err := authenticateOracleProofs(12, proofs, full, fullRand, decoderFor(txs, 0xff)); err != nil {
		t.Fatalf("complete data: %v", err)
	}
}

// A zero value is "no proposal" and has no entry, as GeneratePriceData does.
func TestOracleDataFromProofsSkipsZeroValuesAndSortsByID(t *testing.T) {
	logger.InitLogger()
	txs := map[byte]*transactionsDefinition.Transaction{
		1: nonceTxFor(5, 10, 200, 0),
		2: nonceTxFor(2, 11, 0, 500),
	}
	price, rnd, err := oracleDataFromProofs([][]byte{{1}, {2}}, decoderFor(txs, 0xff))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(price, oracleTriple(5, 10, 200)) || !bytes.Equal(rnd, oracleTriple(2, 11, 500)) {
		t.Fatalf("price=%x rand=%x", price, rnd)
	}
}

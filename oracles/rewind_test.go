package oracles

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// After a rewind from 60 to 53 the node still held oracle submissions for
// heights up to 60. The producer embedded those "future" proofs in block 54,
// which every validator - itself included - rejects ("oracle proof height 60
// not fresh for block 54"), and the strictly-newer save rule refused the fresh
// height-54 submissions: a lone producer was stuck until restarted.

func resetOracleStores(t *testing.T) {
	t.Helper()
	PriceOraclesRWMutex.Lock()
	savedP := PriceOracles
	PriceOracles = map[uint8]PriceOracle{}
	PriceOraclesRWMutex.Unlock()
	oracleProofsRWMutex.Lock()
	savedProofs := oracleProofs
	oracleProofs = map[uint8]oracleProof{}
	oracleProofsRWMutex.Unlock()
	t.Cleanup(func() {
		PriceOraclesRWMutex.Lock()
		PriceOracles = savedP
		PriceOraclesRWMutex.Unlock()
		oracleProofsRWMutex.Lock()
		oracleProofs = savedProofs
		oracleProofsRWMutex.Unlock()
	})
}

func submit(t *testing.T, id int16, height int64) {
	t.Helper()
	da := common.GetDelegatedAccountAddress(id)
	if err := SavePriceOracle(100+int64(id), height, da, 1000); err != nil {
		t.Fatal(err)
	}
	if err := SaveOracleProof(da, height, []byte{byte(id), byte(height)}); err != nil {
		t.Fatal(err)
	}
}

func TestProducerSkipsSubmissionsFromTheFuture(t *testing.T) {
	resetOracleStores(t)
	submit(t, 1, 60) // left over from before a rewind
	submit(t, 2, 54)
	proofs := GenerateOracleProofs(54)
	if len(proofs) != 1 || proofs[0][0] != 2 {
		t.Fatalf("proofs for block 54: %v, want only validator 2's", proofs)
	}
	data, prices, _ := GeneratePriceData(54)
	parsed, _, _, err := ParsePriceData(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(prices) != 1 || len(parsed) != 1 {
		t.Fatalf("price data for block 54 carries %d entries, want only validator 2's", len(parsed))
	}
	if _, ok := parsed[1]; ok {
		t.Fatal("a height-60 price entered the data of block 54")
	}
}

func TestRewindDropsSubmissionsAboveTheNewTip(t *testing.T) {
	resetOracleStores(t)
	submit(t, 1, 60)
	DropSubmissionsAbove(54) // rewound to 53: the next block's nonces are height 54
	submit(t, 1, 54)         // refused before: 54 < stale 60
	proofs := GenerateOracleProofs(54)
	if len(proofs) != 1 || proofs[0][1] != 54 {
		t.Fatalf("after the rewind the fresh height-54 proof is missing: %v", proofs)
	}
	PriceOraclesRWMutex.RLock()
	h := PriceOracles[1].Height
	PriceOraclesRWMutex.RUnlock()
	if h != 54 {
		t.Fatalf("price height %d after the rewind, want the fresh 54", h)
	}
}

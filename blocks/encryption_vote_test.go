package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// nonceTxWithVotes is an oracle nonce carrying the validator's scheme votes,
// laid out as the nonce service writes them: price, rand, then the two
// length-prefixed votes.
func nonceTxWithVotes(id uint8, height int64, vote1, vote2 []byte) *transactionsDefinition.Transaction {
	tx := nonceTxFor(id, height, 1, 1)
	tx.TxData.OptData = append(tx.TxData.OptData, common.BytesToLenAndBytes(vote1)...)
	tx.TxData.OptData = append(tx.TxData.OptData, common.BytesToLenAndBytes(vote2)...)
	return tx
}

func encCfg(t *testing.T, name string, pub, priv, sig int, paused bool) []byte {
	t.Helper()
	b, err := oqs.GenerateBytesFromParams(name, pub, priv, sig, paused)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func falcon512(t *testing.T, paused bool) []byte {
	return encCfg(t, "Falcon-512", 897, 1281, 752, paused)
}
func falcon1024(t *testing.T, paused bool) []byte {
	return encCfg(t, "Falcon-1024", 1793, 2305, 1462, paused)
}
func mayo5(t *testing.T) []byte { return encCfg(t, "MAYO-5", 5554, 40, 964, false) }

// S4-05: votes are read from the signed nonces embedded in the block, and only
// a vote for exactly the proposed config counts.
func TestEncryptionVoteTallyCountsOnlyMatchingVotes(t *testing.T) {
	logger.InitLogger()
	x, y := falcon512(t, true), falcon1024(t, true)
	txs := map[byte]*transactionsDefinition.Transaction{
		1: nonceTxWithVotes(1, 100, x, nil),
		2: nonceTxWithVotes(2, 100, x, nil),
		3: nonceTxWithVotes(3, 100, y, nil),
		4: nonceTxWithVotes(4, 100, nil, x), // a secondary-slot vote is not a primary vote
	}
	stake := map[int]int64{1: 10, 2: 20, 3: 40, 4: 80}
	got, err := tallyEncryptionVotes([][]byte{{1}, {2}, {3}, {4}}, true, x, decoderFor(txs, 0),
		func(id int) int64 { return stake[id] })
	if err != nil {
		t.Fatal(err)
	}
	if got != 30 {
		t.Fatalf("tally = %d, want 30", got)
	}
	if _, err := tallyEncryptionVotes([][]byte{{9}}, true, x, decoderFor(txs, 9), nil); err == nil {
		t.Fatal("an undecodable proof must fail the tally")
	}
}

// Pausing needs a third of the stake; replacing and UN-pausing need two
// thirds. Un-pausing used to need no vote at all.
func TestEncryptionVoteThresholds(t *testing.T) {
	logger.InitLogger()
	live, _ := oqs.FromBytesToEncryptionConfig(falcon512(t, false))
	paused, _ := oqs.FromBytesToEncryptionConfig(falcon512(t, true))
	other, _ := oqs.FromBytesToEncryptionConfig(falcon1024(t, true))
	cases := []struct {
		name          string
		parent, next  oqs.ConfigEnc
		staked, total int64
		want          bool
	}{
		{"pause at 1/3", live, paused, 33, 99, true},
		{"pause below 1/3", live, paused, 32, 99, false},
		{"replace at 2/3", paused, other, 66, 99, true},
		{"replace below 2/3", paused, other, 65, 99, false},
		{"unpause below 2/3", paused, live, 65, 99, false},
		{"unpause at 2/3", paused, live, 66, 99, true},
		{"no stake at all", live, paused, 0, 0, false},
	}
	for _, c := range cases {
		if got := voteThresholdMet(c.parent, c.next, c.staked, c.total); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// S3-06: the shape of a scheme change is judged against the PARENT block's
// config, never the node's globals and never skipped because of IsSyncing.
func TestEncryptionChangeShapeUsesParentConfigEvenWhileSyncing(t *testing.T) {
	logger.InitLogger()
	common.IsSyncing.Store(true)
	defer common.IsSyncing.Store(false)

	liveParent := blockWithEnc(99, falcon512(t, false), mayo5(t))
	pausedParent := blockWithEnc(99, falcon512(t, true), mayo5(t))

	if _, err := checkEncryptionChangeShape(falcon1024(t, true), liveParent, true); err == nil {
		t.Fatal("replacing a live scheme without pausing it first must be rejected")
	}
	if _, err := checkEncryptionChangeShape(falcon1024(t, false), pausedParent, true); err == nil {
		t.Fatal("a replacement scheme must start paused")
	}
	if _, err := checkEncryptionChangeShape(mayo5(t), pausedParent, true); err == nil {
		t.Fatal("both slots may not hold the same scheme")
	}
	if _, err := checkEncryptionChangeShape(encCfg(t, "Falcon-1024", 999, 2305, 1462, true), pausedParent, true); err == nil {
		t.Fatal("an invalid config must be rejected")
	}
	changed, err := checkEncryptionChangeShape(falcon1024(t, true), pausedParent, true)
	if err != nil || !changed {
		t.Fatalf("a well-formed replacement: changed=%v err=%v", changed, err)
	}
	changed, err = checkEncryptionChangeShape(falcon512(t, false), liveParent, true)
	if err != nil || changed {
		t.Fatalf("the parent's own config is no change: changed=%v err=%v", changed, err)
	}
}

// End to end on the pure core: a change is authorised only by the votes in
// the block's own proofs, weighed by the parent's stake.
func TestEncryptionChangeAuthorisedOnlyByBlockProofs(t *testing.T) {
	logger.InitLogger()
	parent := blockWithEnc(99, falcon512(t, false), mayo5(t))
	pause := falcon512(t, true)
	txs := map[byte]*transactionsDefinition.Transaction{
		1: nonceTxWithVotes(1, 100, pause, nil),
		2: nonceTxWithVotes(2, 100, nil, nil),
	}
	stake := func(id int) int64 { return map[int]int64{1: 40, 2: 60}[id] }
	if err := encryptionChangeAuthorised([][]byte{{1}, {2}}, parent, pause, true, 100, 100, decoderFor(txs, 0), stake); err != nil {
		t.Fatalf("40%% of stake may pause: %v", err)
	}
	if err := encryptionChangeAuthorised([][]byte{{2}}, parent, pause, true, 100, 100, decoderFor(txs, 0), stake); err == nil {
		t.Fatal("a change without votes in the block must be rejected")
	}
	if err := encryptionChangeAuthorised([][]byte{{1}}, parent, pause, true, OracleProofsActivationHeight-1, 100, decoderFor(txs, 0), stake); err == nil {
		t.Fatal("below proof activation the proofs are unauthenticated and cannot vote")
	}
}

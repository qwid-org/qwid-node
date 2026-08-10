package oracles

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// The RAND oracle produces the on-chain randomness that smart contracts draw
// on, so what is testable about it must be pinned exactly: who may submit,
// how long a submission counts, how submissions are ordered before hashing,
// and where the 2/3 threshold falls.
//
// Its known limitation is deliberately NOT asserted away here: a producer can
// still bias the result by choosing which submissions to include (subset
// grinding / bias by omission), because there is no canonical submission set.
// That is documented in docs/oracle-randomness-limitation.md and needs
// commit-reveal to fix. These tests cover everything around it.

func resetRand(t *testing.T) {
	t.Helper()
	logger.InitLogger()
	t.Cleanup(logger.CloseLogger)

	RandOraclesRWMutex.Lock()
	RandOracles = make(map[uint8]RandOracle)
	RandOraclesRWMutex.Unlock()

	account.StakingRWMutex.Lock()
	for i := 0; i < 256; i++ {
		account.StakingAccounts[i] = account.StakingAccountsType{
			AllStakingAccounts: make(map[[20]byte]account.StakingAccount),
		}
	}
	account.StakingRWMutex.Unlock()

	t.Cleanup(func() {
		RandOraclesRWMutex.Lock()
		RandOracles = make(map[uint8]RandOracle)
		RandOraclesRWMutex.Unlock()
	})
}

// stakeDelegated gives delegated account id a total staked balance, which is
// what ParseRandData reads to weigh a submission — it never trusts the stake
// written into the block.
func stakeDelegated(t *testing.T, id int, amount int64) {
	t.Helper()
	account.StakingRWMutex.Lock()
	defer account.StakingRWMutex.Unlock()
	addr := [20]byte{}
	addr[19] = byte(id)
	account.StakingAccounts[id].AllStakingAccounts[addr] = account.StakingAccount{
		StakedBalance: amount,
		Address:       addr,
	}
}

func delegatedAddr(id int16) common.Address { return common.GetDelegatedAccountAddress(id) }

// ------------------------------------------------------------- submissions

func TestSaveRandOracleRecordsSubmission(t *testing.T) {
	resetRand(t)

	if err := SaveRandOracle(1234, 100, delegatedAddr(3), 7_000); err != nil {
		t.Fatalf("SaveRandOracle: %v", err)
	}

	RandOraclesRWMutex.RLock()
	defer RandOraclesRWMutex.RUnlock()
	got, ok := RandOracles[3]
	if !ok {
		t.Fatal("submission not stored under the delegated id")
	}
	if got.Rand != 1234 || got.Height != 100 || got.Staked != 7_000 {
		t.Errorf("stored %+v, want rand 1234 height 100 staked 7000", got)
	}
}

func TestSaveRandOracleRejectsInvalidDelegatedID(t *testing.T) {
	resetRand(t)

	for _, id := range []int16{0, 256, 300, -1} {
		if err := SaveRandOracle(1, 100, delegatedAddr(id), 1_000); err == nil {
			t.Errorf("delegated id %d was accepted", id)
		}
	}

	RandOraclesRWMutex.RLock()
	defer RandOraclesRWMutex.RUnlock()
	if len(RandOracles) != 0 {
		t.Fatalf("invalid ids wrote %d entries", len(RandOracles))
	}
}

func TestSaveRandOracleRejectsOlderHeight(t *testing.T) {
	resetRand(t)

	if err := SaveRandOracle(1, 200, delegatedAddr(4), 1_000); err != nil {
		t.Fatalf("first submission: %v", err)
	}
	if err := SaveRandOracle(2, 199, delegatedAddr(4), 1_000); err == nil {
		t.Fatal("a submission from an older height was accepted")
	}
}

// One submission per delegated account per height, first one wins — the same
// rule the voting path was tightened to under AC-M4. Allowing a resubmission at
// the same height let an account replace its own randomness contribution after
// seeing what everyone else had sent, which is a grinding lever on top of the
// documented subset-grinding one.
func TestSaveRandOracleRejectsResubmissionAtSameHeight(t *testing.T) {
	resetRand(t)

	if err := SaveRandOracle(111, 100, delegatedAddr(5), 1_000); err != nil {
		t.Fatalf("first submission: %v", err)
	}
	if err := SaveRandOracle(222, 100, delegatedAddr(5), 1_000); err == nil {
		t.Fatal("a second submission at the same height was accepted")
	}

	RandOraclesRWMutex.RLock()
	defer RandOraclesRWMutex.RUnlock()
	if got := RandOracles[5].Rand; got != 111 {
		t.Fatalf("stored rand = %d, want the first submission 111", got)
	}
}

// The price oracle and the retained proof must follow the same rule, and this
// is not tidiness. blocks.matchOracleData requires the (id, height, value)
// triple in the block to be identical to the one inside the signed proof, so if
// the rand submission keeps the first value while the proof is replaced by a
// later transaction carrying a different one, every block built from that state
// is rejected. The three stores have to agree on which submission won.
func TestSameHeightResubmissionKeepsValueAndProofConsistent(t *testing.T) {
	resetRand(t)
	oracleProofsRWMutex.Lock()
	oracleProofs = make(map[uint8]oracleProof)
	oracleProofsRWMutex.Unlock()

	const id = int16(6)
	first, second := []byte("PROOF-FIRST"), []byte("PROOF-SECOND")

	if err := SavePriceOracle(500, 100, delegatedAddr(id), 1_000); err != nil {
		t.Fatalf("first price: %v", err)
	}
	if err := SaveRandOracle(111, 100, delegatedAddr(id), 1_000); err != nil {
		t.Fatalf("first rand: %v", err)
	}
	if err := SaveOracleProof(delegatedAddr(id), 100, first); err != nil {
		t.Fatalf("first proof: %v", err)
	}

	// A second nonce at the same height — a duplicate or a replay.
	_ = SavePriceOracle(999, 100, delegatedAddr(id), 1_000)
	_ = SaveRandOracle(222, 100, delegatedAddr(id), 1_000)
	_ = SaveOracleProof(delegatedAddr(id), 100, second)

	PriceOraclesRWMutex.RLock()
	gotPrice := PriceOracles[uint8(id)].Price
	PriceOraclesRWMutex.RUnlock()
	RandOraclesRWMutex.RLock()
	gotRand := RandOracles[uint8(id)].Rand
	RandOraclesRWMutex.RUnlock()
	proofs := GenerateOracleProofs(100)

	if gotPrice != 500 {
		t.Errorf("price = %d, want the first submission 500", gotPrice)
	}
	if gotRand != 111 {
		t.Errorf("rand = %d, want the first submission 111", gotRand)
	}
	if len(proofs) != 1 || !bytes.Equal(proofs[0], first) {
		t.Errorf("retained proof = %q, want the one backing the retained values", proofs)
	}
}

// ------------------------------------------------------- window and filters

func TestRandSubmissionCountsUpToWindowEnd(t *testing.T) {
	resetRand(t)
	const submittedAt = int64(100)

	if err := SaveRandOracle(42, submittedAt, delegatedAddr(6), 1_000); err != nil {
		t.Fatalf("submission: %v", err)
	}

	last := submittedAt + common.OraclesHeightDistance
	if _, rands, _ := GenerateRandData(last); len(rands) != 8 {
		t.Fatalf("submission dropped at the last height of its window (%d)", last)
	}
	if _, rands, _ := GenerateRandData(last + 1); len(rands) != 0 {
		t.Fatalf("submission still counted one height past its window")
	}
}

// Unlike the voting tally, GenerateRandData only skips stale entries; it never
// deletes them. An entry therefore stays in the map indefinitely and starts
// counting again if it is ever asked about at a lower height.
func TestExpiredRandSubmissionIsSkippedButRetained(t *testing.T) {
	resetRand(t)
	const submittedAt = int64(100)

	if err := SaveRandOracle(42, submittedAt, delegatedAddr(7), 1_000); err != nil {
		t.Fatalf("submission: %v", err)
	}
	past := submittedAt + common.OraclesHeightDistance + 1
	GenerateRandData(past)

	RandOraclesRWMutex.RLock()
	_, stillThere := RandOracles[7]
	RandOraclesRWMutex.RUnlock()
	if !stillThere {
		t.Fatal("behaviour changed: expired rand submissions are now purged")
	}
	if _, rands, _ := GenerateRandData(submittedAt); len(rands) != 8 {
		t.Fatal("a retained entry did not count again at a height inside its window")
	}
}

// Only strictly positive proposals are aggregated, so a zero or negative
// submission silently contributes nothing — including its stake.
func TestNonPositiveRandIsExcludedFromAggregation(t *testing.T) {
	resetRand(t)

	if err := SaveRandOracle(0, 100, delegatedAddr(8), 5_000); err != nil {
		t.Fatalf("zero submission: %v", err)
	}
	if err := SaveRandOracle(-7, 100, delegatedAddr(9), 5_000); err != nil {
		t.Fatalf("negative submission: %v", err)
	}

	data, rands, staked := GenerateRandData(100)
	if len(rands) != 0 || len(data) != 0 {
		t.Errorf("non-positive proposals were aggregated: %d rand bytes", len(rands))
	}
	if staked != 0 {
		t.Errorf("staked = %d, want 0 — excluded proposals must not carry weight", staked)
	}
}

// ------------------------------------------------------------------ parsing

func TestParseRandDataRejectsTruncatedInput(t *testing.T) {
	resetRand(t)

	entry := oracleEntry(1, 100, 42)
	if _, _, _, err := ParseRandData(entry[:len(entry)-1]); err == nil {
		t.Fatal("a truncated entry was accepted")
	}
	if _, _, _, err := ParseRandData(append(entry, 0x00)); err == nil {
		t.Fatal("a trailing byte was accepted")
	}
}

// The weight of a submission comes from chain state, never from the block, so
// a producer cannot inflate the represented stake by writing a bigger number.
func TestParsedStakeComesFromChainStateNotFromTheBlock(t *testing.T) {
	resetRand(t)
	stakeDelegated(t, 11, 4_000)

	_, _, staked, err := ParseRandData(oracleEntry(11, 100, 42))
	if err != nil {
		t.Fatalf("ParseRandData: %v", err)
	}
	if staked != 4_000 {
		t.Fatalf("staked = %d, want the on-chain 4000", staked)
	}
}

// A round trip must preserve the aggregated proposals byte for byte, since the
// hash is taken over exactly those bytes on both sides.
func TestGenerateParseRoundTripPreservesProposals(t *testing.T) {
	resetRand(t)
	for id, v := range map[int16]int64{12: 111, 13: 222, 14: 333} {
		stakeDelegated(t, int(id), 1_000)
		if err := SaveRandOracle(v, 100, delegatedAddr(id), 1_000); err != nil {
			t.Fatalf("submission %d: %v", id, err)
		}
	}

	data, rands, _ := GenerateRandData(100)
	_, parsedRands, _, err := ParseRandData(data)
	if err != nil {
		t.Fatalf("ParseRandData on generated data: %v", err)
	}
	if !bytes.Equal(rands, parsedRands) {
		t.Fatalf("round trip changed the hashed proposals:\n gen   %x\n parse %x", rands, parsedRands)
	}
}

// ---------------------------------------------------------------- threshold

// CalculateRandOracle requires staked > 2/3 STRICTLY: `staked <= 2*totalStaked/3`
// is the rejection. Note this differs from the voting path, where exactly two
// thirds is enough to replace a scheme. The integer division also truncates, so
// the effective bar sits marginally below a true two thirds.
func TestRandOracleNeedsStrictlyMoreThanTwoThirds(t *testing.T) {
	resetRand(t)
	const total = int64(9_000)

	// Exactly 2/3 must NOT be enough.
	stakeDelegated(t, 20, 6_000)
	if err := SaveRandOracle(42, 100, delegatedAddr(20), 6_000); err != nil {
		t.Fatalf("submission: %v", err)
	}
	if _, _, err := CalculateRandOracle(100, total); err == nil {
		t.Error("exactly two thirds was accepted; the check is documented as strict")
	}

	// One unit above clears it.
	resetRand(t)
	stakeDelegated(t, 21, 6_001)
	if err := SaveRandOracle(42, 100, delegatedAddr(21), 6_001); err != nil {
		t.Fatalf("submission: %v", err)
	}
	if _, _, err := CalculateRandOracle(100, total); err != nil {
		t.Errorf("just above two thirds was rejected: %v", err)
	}
}

func TestRandOracleRejectsWhenNobodySubmitted(t *testing.T) {
	resetRand(t)

	if _, _, err := CalculateRandOracle(100, 9_000); err == nil {
		t.Fatal("a value was produced with no submissions at all")
	}
}

// ------------------------------------------------------- calculate / verify

// The producer and every validator must land on the same number from the same
// submissions, otherwise the block does not validate.
func TestVerifyAcceptsWhatCalculateProduced(t *testing.T) {
	resetRand(t)
	const total = int64(9_000)
	for id, v := range map[int16]int64{22: 111, 23: 222, 24: 333} {
		stakeDelegated(t, int(id), 3_000)
		if err := SaveRandOracle(v, 100, delegatedAddr(id), 3_000); err != nil {
			t.Fatalf("submission %d: %v", id, err)
		}
	}

	rand, randData, err := CalculateRandOracle(100, total)
	if err != nil {
		t.Fatalf("CalculateRandOracle: %v", err)
	}
	if rand == 0 {
		t.Fatal("calculated randomness is zero")
	}
	if !VerifyRandOracle(100, total, rand, randData) {
		t.Fatal("a validator rejected the value its own producer path computed")
	}
}

func TestVerifyRejectsATamperedValue(t *testing.T) {
	resetRand(t)
	const total = int64(9_000)
	for id, v := range map[int16]int64{25: 111, 26: 222, 27: 333} {
		stakeDelegated(t, int(id), 3_000)
		if err := SaveRandOracle(v, 100, delegatedAddr(id), 3_000); err != nil {
			t.Fatalf("submission %d: %v", id, err)
		}
	}

	rand, randData, err := CalculateRandOracle(100, total)
	if err != nil {
		t.Fatalf("CalculateRandOracle: %v", err)
	}
	if VerifyRandOracle(100, total, rand+1, randData) {
		t.Fatal("a value that does not match the submissions was accepted")
	}
}

// Reordering the entries would change the hash, so it must be refused outright
// rather than producing a different-but-accepted number. This is the guard that
// removes producer ordering-grinding.
func TestVerifyRejectsReorderedSubmissions(t *testing.T) {
	resetRand(t)
	stakeDelegated(t, 30, 4_000)
	stakeDelegated(t, 31, 4_000)

	ascending := append(oracleEntry(30, 100, 111), oracleEntry(31, 100, 222)...)
	descending := append(oracleEntry(31, 100, 222), oracleEntry(30, 100, 111)...)

	if _, _, _, err := ParseRandData(ascending); err != nil {
		t.Fatalf("canonical order was rejected: %v", err)
	}
	if VerifyRandOracle(100, 9_000, 12345, descending) {
		t.Fatal("a reordered submission set was accepted")
	}
}

// Below the threshold no randomness can be established, and the block must say
// so by carrying zero. Any other value is a lie about what the submissions
// supported.
func TestBelowThresholdOnlyZeroIsAccepted(t *testing.T) {
	resetRand(t)
	stakeDelegated(t, 32, 1_000)
	data := oracleEntry(32, 100, 42)

	if !VerifyRandOracle(100, 9_000, 0, data) {
		t.Error("zero was rejected below the threshold, where nothing can be established")
	}
	if VerifyRandOracle(100, 9_000, 999, data) {
		t.Error("a non-zero value was accepted below the threshold")
	}
}

// Same submissions must always give the same number — the value is consensus
// data, so any run-to-run variation would fork the chain.
func TestRandCalculationIsDeterministic(t *testing.T) {
	resetRand(t)
	const total = int64(9_000)
	for id, v := range map[int16]int64{40: 111, 41: 222, 42: 333, 43: 444} {
		stakeDelegated(t, int(id), 3_000)
		if err := SaveRandOracle(v, 100, delegatedAddr(id), 3_000); err != nil {
			t.Fatalf("submission %d: %v", id, err)
		}
	}

	first, _, err := CalculateRandOracle(100, total)
	if err != nil {
		t.Fatalf("CalculateRandOracle: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, _, err := CalculateRandOracle(100, total)
		if err != nil {
			t.Fatalf("CalculateRandOracle run %d: %v", i, err)
		}
		if again != first {
			t.Fatalf("run %d produced %d, first run produced %d — map iteration "+
				"order is leaking into consensus data", i, again, first)
		}
	}
}

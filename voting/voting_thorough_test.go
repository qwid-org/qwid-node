package voting

import (
	"bytes"
	"sync"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// Voting decides whether the network pauses or replaces a signature scheme,
// so a wrong answer here is a chain-wide cryptographic decision. These tests
// pin the parts that decide it: who may record a vote, how long a vote counts,
// and exactly where the thresholds fall.
//
// The global vote maps are package state, so every test starts from a clean
// slate and none of them may run in parallel.

func resetVoting(t *testing.T) {
	t.Helper()
	logger.InitLogger()
	t.Cleanup(logger.CloseLogger)
	ResetLastVoting()
	t.Cleanup(ResetLastVoting)
}

// delegated returns the canonical address of delegated account id, which is
// what the node derives before it reaches SaveVotes.
func delegated(id int16) common.Address {
	return common.GetDelegatedAccountAddress(id)
}

func voteValue(b byte) []byte { return []byte{b, b, b} }

// ---------------------------------------------------------------- recording

func TestSaveVoteRecordsValueHeightAndStake(t *testing.T) {
	resetVoting(t)

	if err := SaveVotesEncryption1(voteValue(7), 100, delegated(3), 5_000); err != nil {
		t.Fatalf("SaveVotesEncryption1: %v", err)
	}

	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	got, ok := VotesEncryption1[3]
	if !ok {
		t.Fatal("vote not recorded under the delegated account's id")
	}
	if !bytes.Equal(got.Values, voteValue(7)) {
		t.Errorf("Values = %v", got.Values)
	}
	if got.Height != 100 || got.Staked != 5_000 {
		t.Errorf("Height/Staked = %d/%d, want 100/5000", got.Height, got.Staked)
	}
}

// AC-M4: a delegated account gets one vote per height. A second vote at the
// same height must not overwrite the first, or a node could keep re-voting
// within one block until it liked the tally.
func TestSaveVoteRejectsSecondVoteAtSameHeight(t *testing.T) {
	resetVoting(t)

	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(4), 1_000); err != nil {
		t.Fatalf("first vote: %v", err)
	}
	if err := SaveVotesEncryption1(voteValue(2), 100, delegated(4), 9_999); err == nil {
		t.Fatal("a second vote at the same height was accepted")
	}

	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	if got := VotesEncryption1[4]; !bytes.Equal(got.Values, voteValue(1)) || got.Staked != 1_000 {
		t.Errorf("the rejected vote still overwrote the stored one: %v / %d",
			got.Values, got.Staked)
	}
}

func TestSaveVoteRejectsOlderHeight(t *testing.T) {
	resetVoting(t)

	if err := SaveVotesEncryption1(voteValue(1), 200, delegated(5), 1_000); err != nil {
		t.Fatalf("first vote: %v", err)
	}
	if err := SaveVotesEncryption1(voteValue(2), 199, delegated(5), 1_000); err == nil {
		t.Fatal("a vote from an older height was accepted")
	}
}

func TestSaveVoteAcceptsStrictlyNewerHeight(t *testing.T) {
	resetVoting(t)

	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(6), 1_000); err != nil {
		t.Fatalf("first vote: %v", err)
	}
	if err := SaveVotesEncryption1(voteValue(2), 101, delegated(6), 2_000); err != nil {
		t.Fatalf("newer vote rejected: %v", err)
	}

	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	got := VotesEncryption1[6]
	if !bytes.Equal(got.Values, voteValue(2)) || got.Height != 101 || got.Staked != 2_000 {
		t.Errorf("newer vote did not replace the older one: %v %d %d",
			got.Values, got.Height, got.Staked)
	}
}

// An empty value is a no-op rather than an error, and — importantly — must not
// register an entry that would later contribute its stake to a tally.
func TestSaveVoteWithEmptyValueRecordsNothing(t *testing.T) {
	resetVoting(t)

	if err := SaveVotesEncryption1(nil, 100, delegated(7), 1_000_000); err != nil {
		t.Fatalf("empty vote returned an error: %v", err)
	}

	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	if _, ok := VotesEncryption1[7]; ok {
		t.Fatal("an empty vote created an entry whose stake would count")
	}
}

// The delegated-account id must be inside 1..255. The network path validates
// this before calling in (IsTop128StakingNode bounds-checks), but the guard
// here is the last line of defence and has to hold on its own — including for
// ids that wrap negative through int16.
func TestSaveVoteRejectsOutOfRangeDelegatedAccount(t *testing.T) {
	resetVoting(t)

	for _, id := range []int16{256, 300, -1, -256} {
		addr := delegated(id)
		err1 := SaveVotesEncryption1(voteValue(1), 100, addr, 1_000)
		err2 := SaveVotesEncryption2(voteValue(1), 100, addr, 1_000)
		if err1 == nil || err2 == nil {
			t.Errorf("id %d was accepted (err1=%v err2=%v)", id, err1, err2)
		}
	}

	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	if len(VotesEncryption1) != 0 || len(VotesEncryption2) != 0 {
		t.Fatalf("out-of-range ids wrote into the tally: %d / %d entries",
			len(VotesEncryption1), len(VotesEncryption2))
	}
}

// The two schemes are voted on separately; a vote for one must never be
// counted towards the other.
func TestSchemesAreTalliedIndependently(t *testing.T) {
	resetVoting(t)

	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(8), 4_000); err != nil {
		t.Fatalf("scheme 1 vote: %v", err)
	}

	if _, _, staked := GenerateEncryption2Data(100); staked != 0 {
		t.Fatalf("scheme 2 tally = %d, want 0 — a scheme 1 vote leaked across", staked)
	}
	if _, _, staked := GenerateEncryption1Data(100); staked != 4_000 {
		t.Fatalf("scheme 1 tally = %d, want 4000", staked)
	}
}

// ------------------------------------------------------------ voting window

func TestVoteCountsUpToAndIncludingWindowEnd(t *testing.T) {
	resetVoting(t)
	const votedAt = int64(100)

	if err := SaveVotesEncryption1(voteValue(1), votedAt, delegated(9), 3_000); err != nil {
		t.Fatalf("vote: %v", err)
	}

	last := votedAt + common.VotingHeightDistance
	if _, _, staked := GenerateEncryption1Data(last); staked != 3_000 {
		t.Fatalf("tally at the last height of the window = %d, want 3000", staked)
	}
}

func TestVotePastWindowIsDroppedAndPurged(t *testing.T) {
	resetVoting(t)
	const votedAt = int64(100)

	if err := SaveVotesEncryption1(voteValue(1), votedAt, delegated(10), 3_000); err != nil {
		t.Fatalf("vote: %v", err)
	}

	past := votedAt + common.VotingHeightDistance + 1
	if _, _, staked := GenerateEncryption1Data(past); staked != 0 {
		t.Fatalf("an expired vote still counted: %d", staked)
	}

	// Purging is permanent: asking again at a height back inside the original
	// window must not resurrect it.
	if _, _, staked := GenerateEncryption1Data(votedAt); staked != 0 {
		t.Fatalf("an expired vote came back at a lower height: %d", staked)
	}
	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	if _, ok := VotesEncryption1[10]; ok {
		t.Fatal("expired vote left in the map")
	}
}

func TestTallySumsStakeAcrossDelegatedAccounts(t *testing.T) {
	resetVoting(t)

	for i, stake := range map[int16]int64{11: 1_000, 12: 2_000, 13: 3_500} {
		if err := SaveVotesEncryption1(voteValue(byte(i)), 100, delegated(i), stake); err != nil {
			t.Fatalf("vote for %d: %v", i, err)
		}
	}

	_, values, staked := GenerateEncryption1Data(100)
	if staked != 6_500 {
		t.Errorf("summed stake = %d, want 6500", staked)
	}
	if len(values) != 3 {
		t.Errorf("values = %d entries, want 3", len(values))
	}
}

// The encoded blob is what travels in the block, so its framing matters:
// one id byte, then the 8-byte height, then the length-prefixed value.
func TestEncodedVoteDataFraming(t *testing.T) {
	resetVoting(t)

	if err := SaveVotesEncryption1(voteValue(9), 4242, delegated(14), 1_000); err != nil {
		t.Fatalf("vote: %v", err)
	}

	data, _, _ := GenerateEncryption1Data(4242)
	if len(data) < 9 {
		t.Fatalf("encoded data too short: %d bytes", len(data))
	}
	if data[0] != 14 {
		t.Errorf("first byte = %d, want the delegated account id 14", data[0])
	}
	if h := common.GetInt64FromByte(data[1:9]); h != 4242 {
		t.Errorf("encoded height = %d, want 4242", h)
	}
	if !bytes.Contains(data, voteValue(9)) {
		t.Error("the vote value is missing from the encoded data")
	}
}

// ---------------------------------------------------------------- thresholds

func TestPausingNeedsExactlyOneThird(t *testing.T) {
	resetVoting(t)
	const total = int64(9_000)

	// 1/3 exactly passes.
	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(20), 3_000); err != nil {
		t.Fatalf("vote: %v", err)
	}
	if !VerifyEncryptionForPausing(100, total, true, voteValue(1)) {
		t.Error("exactly one third was rejected for pausing")
	}
}

func TestPausingRejectsJustBelowOneThird(t *testing.T) {
	resetVoting(t)
	const total = int64(9_000)

	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(21), 2_999); err != nil {
		t.Fatalf("vote: %v", err)
	}
	if VerifyEncryptionForPausing(100, total, true, voteValue(1)) {
		t.Error("one unit below a third was accepted for pausing")
	}
}

func TestReplacingNeedsExactlyTwoThirds(t *testing.T) {
	resetVoting(t)
	const total = int64(9_000)

	if err := SaveVotesEncryption2(voteValue(1), 100, delegated(22), 6_000); err != nil {
		t.Fatalf("vote: %v", err)
	}
	if !VerifyEncryptionForReplacing(100, total, false, voteValue(1)) {
		t.Error("exactly two thirds was rejected for replacing")
	}
}

func TestReplacingRejectsJustBelowTwoThirds(t *testing.T) {
	resetVoting(t)
	const total = int64(9_000)

	if err := SaveVotesEncryption2(voteValue(1), 100, delegated(23), 5_999); err != nil {
		t.Fatalf("vote: %v", err)
	}
	if VerifyEncryptionForReplacing(100, total, false, voteValue(1)) {
		t.Error("one unit below two thirds was accepted for replacing")
	}
}

// A third of the supply does not fit float32's ~7 significant digits, which is
// why the comparison is integer. One unit either side of the boundary must
// still decide correctly at chain-sized stakes.
func TestThresholdsAreExactAtChainSizedStakes(t *testing.T) {
	resetVoting(t)
	const total = int64(300_000_000_000_000_003) // 3 * 1e17 + 3

	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(24), 100_000_000_000_000_001); err != nil {
		t.Fatalf("vote: %v", err)
	}
	if !VerifyEncryptionForPausing(100, total, true, voteValue(1)) {
		t.Error("exact third at chain scale was rejected")
	}

	resetVoting(t)
	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(24), 100_000_000_000_000_000); err != nil {
		t.Fatalf("vote: %v", err)
	}
	if VerifyEncryptionForPausing(100, total, true, voteValue(1)) {
		t.Error("one unit below the exact third at chain scale was accepted")
	}
}

// An expired vote must not keep a scheme change alive.
func TestExpiredVotesDoNotReachThreshold(t *testing.T) {
	resetVoting(t)
	const total = int64(9_000)

	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(25), 9_000); err != nil {
		t.Fatalf("vote: %v", err)
	}
	past := int64(100) + common.VotingHeightDistance + 1
	if VerifyEncryptionForReplacing(past, total, true, voteValue(1)) {
		t.Error("a vote past its window still authorised a scheme replacement")
	}
}

// Nobody voted, so nothing may be authorised — whatever the total stake says.
//
// The ratio alone did not cover this: with totalStaked at zero the comparison
// `staked*3 < totalStaked` reads `0 < 0`, which is false, so both checks
// returned true and a signature-scheme change would have been approved on zero
// support.
func TestNoVotesAuthorisesNothing(t *testing.T) {
	resetVoting(t)

	for _, total := range []int64{0, -1, 9_000} {
		if VerifyEncryptionForPausing(100, total, true, voteValue(1)) {
			t.Errorf("pausing approved with no votes at totalStaked=%d", total)
		}
		if VerifyEncryptionForReplacing(100, total, true, voteValue(1)) {
			t.Errorf("replacing approved with no votes at totalStaked=%d", total)
		}
	}
}

// A threshold is a fraction OF something. With no total stake to measure
// against there is no fraction, so nothing can clear it — even when somebody
// voted with a real stake. That combination means the staking state is
// inconsistent (the total cannot be below a voter's own stake), and an
// inconsistent state must not be read as consent.
func TestNonPositiveTotalStakeAuthorisesNothing(t *testing.T) {
	for _, total := range []int64{0, -1} {
		resetVoting(t)
		if err := SaveVotesEncryption1(voteValue(1), 100, delegated(28), 5_000); err != nil {
			t.Fatalf("vote: %v", err)
		}
		if VerifyEncryptionForPausing(100, total, true, voteValue(1)) {
			t.Errorf("pausing approved at totalStaked=%d despite no measurable threshold", total)
		}

		resetVoting(t)
		if err := SaveVotesEncryption2(voteValue(1), 100, delegated(28), 5_000); err != nil {
			t.Fatalf("vote: %v", err)
		}
		if VerifyEncryptionForReplacing(100, total, false, voteValue(1)) {
			t.Errorf("replacing approved at totalStaked=%d despite no measurable threshold", total)
		}
	}
}

// Expiry must reach the same conclusion: once the last vote falls out of its
// window the tally is empty, and an empty tally authorises nothing.
func TestTallyEmptiedByExpiryAuthorisesNothing(t *testing.T) {
	resetVoting(t)

	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(27), 9_000); err != nil {
		t.Fatalf("vote: %v", err)
	}
	past := int64(100) + common.VotingHeightDistance + 1

	if VerifyEncryptionForPausing(past, 0, true, voteValue(1)) {
		t.Error("pausing approved after the only vote expired")
	}
	if VerifyEncryptionForReplacing(past, 0, true, voteValue(1)) {
		t.Error("replacing approved after the only vote expired")
	}
}

// ---------------------------------------------------------- reset and state

func TestResetLastVotingSetsAfterResetFlag(t *testing.T) {
	resetVoting(t)
	AfterReset = false

	ResetLastVoting()

	if !AfterReset {
		t.Error("AfterReset was not raised by ResetLastVoting")
	}
}

// Verify* is not a pure query: it tallies through GenerateEncryptionXData,
// which purges expired entries. Two calls around a window boundary therefore
// see different state, and block processing calls it more than once.
func TestVerifyPurgesExpiredVotesAsASideEffect(t *testing.T) {
	resetVoting(t)

	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(26), 1_000); err != nil {
		t.Fatalf("vote: %v", err)
	}
	past := int64(100) + common.VotingHeightDistance + 1
	VerifyEncryptionForPausing(past, 9_000, true, voteValue(1))

	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	if _, ok := VotesEncryption1[26]; ok {
		t.Error("expected the expired vote to have been purged by the check")
	}
}

// Votes arrive from concurrent peer handlers; run under -race.
func TestConcurrentVotesDoNotRace(t *testing.T) {
	resetVoting(t)

	var wg sync.WaitGroup
	for id := int16(30); id < 60; id++ {
		wg.Add(1)
		go func(id int16) {
			defer wg.Done()
			_ = SaveVotesEncryption1(voteValue(byte(id)), int64(id), delegated(id), int64(id)*100)
			_ = SaveVotesEncryption2(voteValue(byte(id)), int64(id), delegated(id), int64(id)*100)
			GenerateEncryption1Data(int64(id))
			GenerateEncryption2Data(int64(id))
		}(id)
	}
	wg.Wait()
}

package voting

import "testing"

// The threshold is meant to answer "does a third of the stake back THIS
// change", but the tally summed every live vote regardless of what it was for.
// Two validators voting for two different things therefore authorised either of
// them — and, across the two verifiers, a vote to replace the scheme counted
// towards pausing it and vice versa.
func TestPausingCountsOnlyVotesForTheProposedChange(t *testing.T) {
	resetVoting(t)
	const total = int64(9_000)

	// Neither proposal has a third behind it on its own; together they do.
	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(30), 2_500); err != nil {
		t.Fatalf("vote A: %v", err)
	}
	if err := SaveVotesEncryption1(voteValue(2), 100, delegated(31), 2_500); err != nil {
		t.Fatalf("vote B: %v", err)
	}

	if VerifyEncryptionForPausing(100, total, true, voteValue(1)) {
		t.Error("pausing was authorised by stake that had voted for a different change")
	}
	if VerifyEncryptionForPausing(100, total, true, voteValue(2)) {
		t.Error("pausing was authorised by stake that had voted for a different change")
	}
}

// The positive control: agreement must still pass, or the fix has simply
// broken voting instead of correcting it.
func TestPausingPassesWhenTheStakeAgrees(t *testing.T) {
	resetVoting(t)
	const total = int64(9_000)

	if err := SaveVotesEncryption1(voteValue(7), 100, delegated(32), 2_000); err != nil {
		t.Fatalf("vote A: %v", err)
	}
	if err := SaveVotesEncryption1(voteValue(7), 100, delegated(33), 1_000); err != nil {
		t.Fatalf("vote B: %v", err)
	}

	if !VerifyEncryptionForPausing(100, total, true, voteValue(7)) {
		t.Error("a third of the stake agreeing on one change was refused")
	}
}

func TestReplacingCountsOnlyVotesForTheProposedChange(t *testing.T) {
	resetVoting(t)
	const total = int64(9_000)

	// 2/3 needed for a replacement. Split across two different proposals.
	if err := SaveVotesEncryption2(voteValue(1), 100, delegated(34), 3_000); err != nil {
		t.Fatalf("vote A: %v", err)
	}
	if err := SaveVotesEncryption2(voteValue(2), 100, delegated(35), 3_000); err != nil {
		t.Fatalf("vote B: %v", err)
	}

	if VerifyEncryptionForReplacing(100, total, false, voteValue(1)) {
		t.Error("a replacement was authorised by stake that had voted for a different change")
	}
}

// An unknown proposal has nobody behind it, so it must never clear a threshold
// however much stake is voting on other things.
func TestUnvotedProposalIsNeverAuthorised(t *testing.T) {
	resetVoting(t)
	const total = int64(9_000)

	if err := SaveVotesEncryption1(voteValue(1), 100, delegated(36), 9_000); err != nil {
		t.Fatalf("vote: %v", err)
	}

	if VerifyEncryptionForPausing(100, total, true, voteValue(99)) {
		t.Error("a proposal nobody voted for was authorised")
	}
}

package voting

import "testing"

// TestResetLastVotingClearsAllIndices verifies AC-M5: ResetLastVoting deletes
// every index 0..255 inclusive, including 255 which the old uint8 loop skipped.
func TestResetLastVotingClearsAllIndices(t *testing.T) {
	VotesEncryptionMutex.Lock()
	for i := 0; i < 256; i++ {
		VotesEncryption1[uint8(i)] = Votes{Height: 1}
		VotesEncryption2[uint8(i)] = Votes{Height: 1}
	}
	VotesEncryptionMutex.Unlock()

	ResetLastVoting()

	VotesEncryptionMutex.Lock()
	defer VotesEncryptionMutex.Unlock()
	if len(VotesEncryption1) != 0 {
		t.Fatalf("VotesEncryption1 not fully cleared: %d entries remain (e.g. index 255 = %v present: %t)",
			len(VotesEncryption1), VotesEncryption1[255], func() bool { _, ok := VotesEncryption1[255]; return ok }())
	}
	if len(VotesEncryption2) != 0 {
		t.Fatalf("VotesEncryption2 not fully cleared: %d entries remain", len(VotesEncryption2))
	}
}

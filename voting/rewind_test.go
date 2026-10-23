package voting

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Same failure as the oracle stores: votes from heights above a rewind's new
// tip made every fresh vote "invalid height" until the chain regrew past them.
func TestRewindDropsVotesAboveTheNewTip(t *testing.T) {
	VotesEncryptionMutex.Lock()
	saved1, saved2 := VotesEncryption1, VotesEncryption2
	VotesEncryption1, VotesEncryption2 = map[uint8]Votes{}, map[uint8]Votes{}
	VotesEncryptionMutex.Unlock()
	t.Cleanup(func() {
		VotesEncryptionMutex.Lock()
		VotesEncryption1, VotesEncryption2 = saved1, saved2
		VotesEncryptionMutex.Unlock()
	})
	da := common.GetDelegatedAccountAddress(1)
	if err := SaveVotesEncryption1([]byte{1}, 60, da, 10); err != nil {
		t.Fatal(err)
	}
	if err := SaveVotesEncryption2([]byte{1}, 60, da, 10); err != nil {
		t.Fatal(err)
	}
	DropVotesAbove(54)
	if err := SaveVotesEncryption1([]byte{2}, 54, da, 10); err != nil {
		t.Fatalf("a fresh primary vote was refused after the rewind: %v", err)
	}
	if err := SaveVotesEncryption2([]byte{2}, 54, da, 10); err != nil {
		t.Fatalf("a fresh secondary vote was refused after the rewind: %v", err)
	}
}

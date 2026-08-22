package syncServices

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/message"
)

// withGenesisHash pins the node's genesis hash for one test, so the check does
// not depend on whatever chain the suite's database happens to hold.
func withGenesisHash(t *testing.T, h []byte) {
	t.Helper()
	saved := localGenesisHash
	localGenesisHash = h
	t.Cleanup(func() { localGenesisHash = saved })
}

func TestWithGenesisHashRestores(t *testing.T) {
	original := localGenesisHash

	t.Run("inner", func(t *testing.T) {
		withGenesisHash(t, []byte{1, 2, 3})
		if !bytes.Equal(localGenesisHash, []byte{1, 2, 3}) {
			t.Fatal("withGenesisHash did not set the hash")
		}
	})

	if !bytes.Equal(localGenesisHash, original) {
		t.Fatalf("withGenesisHash did not restore the hash: got %x, want %x", localGenesisHash, original)
	}
}

// TestGenerateSyncMsgHeightCarriesGenesis: a peer cannot check our chain against
// its own unless we say which chain we are on.
func TestGenerateSyncMsgHeightCarriesGenesis(t *testing.T) {
	want := bytes.Repeat([]byte{0xab}, 32)
	withGenesisHash(t, want)

	raw := generateSyncMsgHeight()
	if len(raw) == 0 {
		t.Skip("generateSyncMsgHeight needs a chain in the database")
	}

	isValid, amsg := message.CheckValidMessage(raw)
	if !isValid {
		t.Fatal("generateSyncMsgHeight produced a message that does not validate")
	}
	txn := amsg.(message.TransactionsMessage).GetTransactionsBytes()

	got := txn[[2]byte{'G', 'B'}]
	if len(got) != 1 {
		t.Fatalf("GB entries = %d, expected 1", len(got))
	}
	if !bytes.Equal(got[0], want) {
		t.Fatalf("GB = %x, expected %x", got[0], want)
	}
}

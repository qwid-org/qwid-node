package clientrpc

import "testing"

// S7-05: only the node's explicit acceptance counts as success.
func TestTransactionAccepted(t *testing.T) {
	if err := TransactionAccepted([]byte("transaction sent")); err != nil {
		t.Fatalf("accepted transaction reported as %v", err)
	}
	for _, reply := range []string{"transaction rejected: insufficient funds", "Timeout", ""} {
		if err := TransactionAccepted([]byte(reply)); err == nil {
			t.Fatalf("%q treated as success", reply)
		}
	}
}

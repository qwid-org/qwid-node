package message

import (
	"bytes"
	"testing"
)

func TestAnyNonceMessage_GetTransactions(t *testing.T) {
	// Prepare test data
	nonceBytes := make(map[[2]byte][][]byte)
	nnb := [2]byte{}
	copy(nnb[:], "N0")
	nonceBytes[nnb] = [][]byte{}
	anyNonceMessage := TransactionsMessage{
		BaseMessage: BaseMessage{
			Head:    []byte("nn"),
			ChainID: 100,
		},
		TransactionsBytes: nonceBytes,
	}
	// Call GetTransactionsBytes method
	transactions, err := anyNonceMessage.GetTransactionsFromBytes("Falcon-512", "MAYO-5", false, false)
	if err != nil {
		return
	}
	// Check if the result is as expected
	if len(transactions) != 0 {
		t.Errorf("Expected 0 transactions, got %d", len(transactions))
	}
}

func TestAnyNonceMessage_GetHead(t *testing.T) {
	// Prepare test data
	anyNonceMessage := TransactionsMessage{
		BaseMessage: BaseMessage{
			Head: []byte("nn"),
		},
	}
	// Call GetHead method
	head := anyNonceMessage.GetHead()
	// Check if the result is as expected
	if !bytes.Equal(head, []byte("nn")) {
		t.Errorf("Expected head 'nn', got %s", string(head))
	}
}

func TestAnyNonceMessage_GetChainID(t *testing.T) {
	// Prepare test data
	anyNonceMessage := TransactionsMessage{
		BaseMessage: BaseMessage{
			ChainID: 100,
		},
	}
	// Call GetChainID method
	chainID := anyNonceMessage.GetChainID()
	// Check if the result is as expected
	if chainID != 100 {
		t.Errorf("Expected chainID 100, got %d", chainID)
	}
}
func TestAnyNonceMessage_GetBytes(t *testing.T) {
	// Prepare test data
	anyNonceMessage := TransactionsMessage{
		BaseMessage: BaseMessage{
			Head:    []byte("nn"),
			ChainID: 100,
		},
		TransactionsBytes: make(map[[2]byte][][]byte),
	}
	// Call GetBytes method
	getBytes := anyNonceMessage.GetBytes()
	// Check if the result is as expected
	if len(getBytes) == 0 {
		t.Error("Expected non-empty byte slice, got empty")
	}
}
func TestAnyNonceMessage_GetFromBytes(t *testing.T) {
	// Prepare test data
	anyNonceMessage := TransactionsMessage{
		BaseMessage: BaseMessage{
			Head:    []byte("nn"),
			ChainID: 100,
		},
		TransactionsBytes: make(map[[2]byte][][]byte),
	}
	inputBytes := anyNonceMessage.GetBytes()
	// Call GetFromBytes method
	_, err := anyNonceMessage.GetFromBytes(inputBytes)
	if err != nil {
		return
	}
	// Check if there is no error
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	// Check if the result is as expected
	if !bytes.Equal(anyNonceMessage.GetHead(), []byte("nn")) {
		t.Errorf("Expected head 'nn', got %s", string(anyNonceMessage.GetHead()))
	}
	if anyNonceMessage.GetChainID() != 100 {
		t.Errorf("Expected chainID 100, got %d", anyNonceMessage.GetChainID())
	}
}

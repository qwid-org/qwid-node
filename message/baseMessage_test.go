package message

import (
	"bytes"
	"github.com/qwid-org/qwid-node/common"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBaseMessage_GetBytes(t *testing.T) {
	m := BaseMessage{
		Head:    []byte("nn"),
		ChainID: common.GetChainID(),
	}

	result := m.GetBytes()
	m.GetFromBytes(result)
	result2 := m.GetBytes()
	if !bytes.Equal(result, result2) {
		t.Errorf("Expected %v, got %v", result2, result)
	}
}
func TestBaseMessage_GetFromBytes(t *testing.T) {
	m := BaseMessage{
		Head:    []byte("nn"),
		ChainID: common.GetChainID(),
	}
	data := m.GetBytes()
	m.GetFromBytes(data)
	data2 := m.GetBytes()
	if !bytes.Equal(m.Head, []byte("nn")) {
		t.Errorf("Expected head %v, got %v", []byte("nn"), m.Head)
	}
	if m.ChainID != common.GetChainID() {
		t.Errorf("Expected chainID %v, got %v", common.GetChainID(), m.ChainID)
	}
	assert.Equal(t, data, data2)
}

func TestCheckMessage(t *testing.T) {
	//common.ValidChains = []uint8{2}
	//m := BaseMessage{
	//	Head:    []byte{0x01, 0x02},
	//	ChainID: common.GetChainID(),
	//	Chain:   2,
	//}
	//if !CheckMessage(&m) {
	//	t.Errorf("Expected message to be valid")
	//}
	//m.Head = []byte{0x03, 0x04}
	//if CheckMessage(m) {
	//	t.Errorf("Expected message to be invalid due to invalid head")
	//}
	//m.Head = []byte{0x01, 0x02}
	//m.ChainID = 2
	//if CheckMessage(m) {
	//	t.Errorf("Expected message to be invalid due to invalid chainID")
	//}
	//m.ChainID = 1
	//m.Chain = 3
	//if CheckMessage(m) {
	//	t.Errorf("Expected message to be invalid due to invalid chain")
	//}
}

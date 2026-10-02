package message

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// S1-12: re-serializing a decoded header must not write into the buffer it
// was decoded from - other parts of the message still read that buffer.
func TestBaseMessageDoesNotAliasInput(t *testing.T) {
	in := append([]byte("nn"), common.GetByteInt16(common.GetChainID())...)
	in = append(in, 0xAA, 0xBB) // stands for the rest of the message
	snapshot := append([]byte(nil), in...)
	var m BaseMessage
	m.GetFromBytes(in[:4])
	m.ChainID = 99
	_ = m.GetBytes()
	if !bytes.Equal(in, snapshot) {
		t.Fatalf("decoding and re-encoding changed the input: %x -> %x", snapshot, in)
	}
}

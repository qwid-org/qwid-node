package message

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Construct raw envelopes so duplicate keys and negative counts cannot be
// normalized away by the production map-based encoder.
func securityEnvelope(groups int32) []byte {
	b := append([]byte("tx"), common.GetByteInt16(common.GetChainID())...)
	return append(b, common.GetByteInt32(groups)...)
}

func securityGroup(b []byte, key string, count int32, withEmptyItems bool) []byte {
	b = append(b, key...)
	b = append(b, common.GetByteInt32(count)...)
	if withEmptyItems {
		for i := int32(0); i < count; i++ {
			b = append(b, 0, 0, 0, 0)
		}
	}
	return b
}

func TestQWID02RejectsUnboundedCounts(t *testing.T) {
	overItems := securityGroup(securityEnvelope(1), "TT", int32(common.MaxTransactionsPerBlock)+1, true)
	combined := securityGroup(securityEnvelope(2), "TT", 2500, true)
	combined = securityGroup(combined, "BB", 2501, true)
	groups := securityEnvelope(17)
	for i := 0; i < 17; i++ {
		groups = securityGroup(groups, fmt.Sprintf("%02d", i), 0, false)
	}
	duplicate := securityGroup(securityEnvelope(2), "TT", 1, true)
	duplicate = securityGroup(duplicate, "TT", 1, true)
	for name, raw := range map[string][]byte{
		"single group over budget": overItems,
		"aggregate over budget":    combined,
		"too many groups":          groups,
		"negative groups":          securityEnvelope(-1),
		"negative items":           securityGroup(securityEnvelope(1), "TT", -1, false),
		"duplicate groups":         duplicate,
		"impossible group count":   securityEnvelope(16),
		"impossible item count":    securityGroup(securityEnvelope(1), "TT", 5000, false),
		"max signed item count":    securityGroup(securityEnvelope(1), "TT", 1<<31-1, false),
		"trailing bytes":           append(securityEnvelope(0), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := (TransactionsMessage{}).GetFromBytes(raw); err == nil {
				t.Fatal("hostile envelope accepted")
			}
		})
	}
}

func TestQWID02SupportedEnvelopesRoundTrip(t *testing.T) {
	items := func(count int, width int) [][]byte {
		out := make([][]byte, count)
		for i := range out {
			out[i] = bytes.Repeat([]byte{byte(i)}, width)
		}
		return out
	}
	for _, tc := range []struct {
		head   string
		fields map[[2]byte][][]byte
	}{
		{"tx", map[[2]byte][][]byte{{'T', 'T'}: nil}}, // Keepalive.
		{"tx", map[[2]byte][][]byte{{'T', 'T'}: items(int(common.MaxTransactionsPerBlock), 32)}},
		{"st", map[[2]byte][][]byte{{'T', 'T'}: items(int(common.MaxTransactionsPerBlock), 32)}},
		{"bt", map[[2]byte][][]byte{{'T', 'T'}: items(common.MaxNumberTransactionInChunk, 32)}},
		{"bx", map[[2]byte][][]byte{{'T', 'T'}: items(common.MaxNumberTransactionInChunk, 1024)}},
		{"bz", map[[2]byte][][]byte{{'T', 'T'}: items(1, 1024)}},
		{"nn", map[[2]byte][][]byte{{'N', 'N'}: items(1, 1024)}},
		{"bl", map[[2]byte][][]byte{{'N', 0}: items(1, 1024)}},
		{"sh", map[[2]byte][][]byte{
			{'I', 'H'}: items(int(common.NumberOfHashesInBucket)+1, 8),
			{'H', 'V'}: items(int(common.NumberOfHashesInBucket)+1, 1024),
		}},
		{"hi", map[[2]byte][][]byte{
			{'L', 'H'}: items(1, 8), {'L', 'B'}: items(1, 32),
			{'G', 'B'}: items(1, 32), {'P', 'P'}: items(common.MaxPeersSharedInHi, 4),
		}},
		{"gh", map[[2]byte][][]byte{{'B', 'H'}: items(1, 8), {'E', 'H'}: items(1, 8)}},
	} {
		t.Run(tc.head, func(t *testing.T) {
			original := TransactionsMessage{BaseMessage: BaseMessage{
				Head: []byte(tc.head), ChainID: common.GetChainID(),
			}, TransactionsBytes: tc.fields}
			ok, decoded := CheckValidMessage(original.GetBytes())
			if !ok || !reflect.DeepEqual(decoded.GetTransactionsBytes(), original.TransactionsBytes) {
				t.Fatal("supported envelope did not round-trip")
			}
		})
	}
}

func TestQWID02RejectsTruncatedEnvelopes(t *testing.T) {
	wire := securityGroup(securityEnvelope(2), "TT", 2, true)
	wire = securityGroup(wire, "BB", 1, true)
	for end := 0; end < len(wire); end++ {
		if _, err := (TransactionsMessage{}).GetFromBytes(wire[:end]); err == nil {
			t.Fatalf("truncation at %d accepted", end)
		}
	}
}

package tcpip

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// TestNonceTopicFitsAFullBlock guards the failure that stalled the chain after
// ~30k transactions were submitted: whole blocks are broadcast over the nonce
// topic (services.BroadcastBlock), but that topic was capped at 64KB as though
// it only ever carried nonces. Blocks stayed under the cap while they were
// nearly empty, so the mismatch only surfaced once the pool filled them, at
// which point every peer rejected every block as "too long message received".
func TestNonceTopicFitsAFullBlock(t *testing.T) {
	// A block serialises its header plus one 32-byte hash per transaction.
	fullBlock := int32(common.MaxTransactionsPerBlock) * int32(common.HashLength)

	for _, topic := range [][2]byte{NonceTopic, SelfNonceTopic} {
		cap := MaxMessageSizeForTopic(topic)
		if cap <= fullBlock {
			t.Fatalf("topic %c%c caps messages at %d bytes, but a full block needs more than %d",
				topic[0], topic[1], cap, fullBlock)
		}
	}
}

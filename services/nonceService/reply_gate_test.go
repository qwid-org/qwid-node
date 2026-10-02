package nonceServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// S2-09: replies are nonces too; a syncing node, or one that is not an
// eligible producer, must not emit them.
func TestNonceEmissionGate(t *testing.T) {
	common.IsSyncing.Store(true)
	defer common.IsSyncing.Store(false)
	if mayEmitNonce() {
		t.Fatal("a syncing node may not emit nonces")
	}
	common.IsSyncing.Store(false)
	if mayEmitNonce() {
		t.Fatal("a node without an eligible producer wallet may not emit nonces")
	}
}

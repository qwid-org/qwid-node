package blocks

import (
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
)

// S3-09: applying a scheme change must not depend on a helper goroutine. It
// used to hand the config to the nonce service over an unbuffered channel, so
// without that service running the block application blocked forever.
func TestSetVoteEncryptionNeedsNoHelperGoroutine(t *testing.T) {
	enc, err := oqs.GenerateBytesFromParams(common.SigName(), common.PubKeyLength(false), common.PrivateKeyLength(), common.SignatureLength(false), common.IsPaused())
	if err != nil {
		t.Skipf("liboqs unavailable: %v", err)
	}
	done := make(chan struct{})
	go func() {
		SetVoteEncryption(enc, true)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SetVoteEncryption blocked")
	}
}

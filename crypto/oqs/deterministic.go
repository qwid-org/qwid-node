package oqs

import (
	"crypto/sha512"
	"errors"
	"io"

	oqsrand "github.com/wonabru/qwid-node/crypto/oqs/rand"
	"github.com/wonabru/qwid-node/logger"
	"golang.org/x/crypto/hkdf"
)

// detKeygenInfo separates the keygen byte stream from any other use of the same
// per-key seed. Changing it invalidates every existing wallet — it is pinned by
// the known-answer test.
const detKeygenInfo = "qwid-oqs-keygen-v1"

// minSeedLength is the smallest seed accepted for deterministic keygen. Anything
// shorter would cap key security below the scheme's own level.
const minSeedLength = 32

// GenerateKeyPairFromSeed generates the key pair that seed determines, instead of
// drawing from the system RNG. It returns the public key and how many bytes
// liboqs pulled from the deterministic stream; the byte count is what lets a test
// pin liboqs' behaviour, because a change there would make every existing
// recovery phrase restore a different wallet.
//
// The deterministic RNG is global to the liboqs process, so it is installed and
// removed while holding randMutex — the same lock Sign holds. Signing therefore
// can never observe it, and Falcon's per-signature salt always comes from the
// system CSPRNG.
func (sig *Signature) GenerateKeyPairFromSeed(seed []byte) ([]byte, int, error) {
	if len(seed) < minSeedLength {
		return nil, 0, errors.New("seed must be at least 32 bytes for deterministic keygen")
	}

	stream := hkdf.Expand(sha512.New, seed, []byte(detKeygenInfo))
	drawn := 0
	var streamErr error

	randMutex.Lock()
	defer randMutex.Unlock()

	if err := oqsrand.RandomBytesCustomAlgorithm(func(out []byte, n int) {
		if n > len(out) {
			n = len(out)
		}
		if _, err := io.ReadFull(stream, out[:n]); err != nil {
			if streamErr == nil {
				streamErr = err
			}
			return
		}
		drawn += n
	}); err != nil {
		return nil, 0, err
	}
	// Runs before the randMutex unlock above: defers are LIFO, so the system RNG
	// is back in place while the lock still keeps signers out. Also covers a panic
	// from inside liboqs.
	defer restoreSystemRNG()

	pub, err := sig.generateKeyPairUnlocked()
	if err != nil {
		return nil, drawn, err
	}
	if streamErr != nil {
		return nil, drawn, streamErr
	}
	return pub, drawn, nil
}

// restoreSystemRNG puts liboqs back on the system CSPRNG. Failing to restore it
// would leave the node signing with a deterministic RNG, which publishes the
// private key through repeated salts — halting is the lesser harm.
func restoreSystemRNG() {
	if err := oqsrand.RandomBytesSwitchAlgorithm("system"); err != nil {
		logger.GetLogger().Fatal("cannot restore the system RNG after deterministic keygen; "+
			"continuing would sign with a predictable salt and leak the private key: ", err)
	}
}

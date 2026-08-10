package oqs

import (
	"crypto/sha512"
	"errors"
	"io"

	oqsrand "github.com/qwid-org/qwid-node/crypto/oqs/rand"
	"github.com/qwid-org/qwid-node/logger"
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
//
// If the HKDF stream fails partway through a draw, liboqs still gets fed
// whatever the callback wrote — the caller-provided buffer is zero-filled, so
// a short read leaves it partly zero. That would let generateKeyPairUnlocked
// write a secret key derived from partly-zero randomness. On any error return
// below, that secret key (if written) is wiped so the receiver is never left
// holding compromised, but seemingly usable, key material.
func (sig *Signature) GenerateKeyPairFromSeed(seed []byte) (pub []byte, drawn int, err error) {
	if len(seed) < minSeedLength {
		return nil, 0, errors.New("seed must be at least 32 bytes for deterministic keygen")
	}

	stream := hkdf.Expand(sha512.New, seed, []byte(detKeygenInfo))
	var streamErr error

	randMutex.Lock()
	defer randMutex.Unlock()

	defer func() {
		if err != nil {
			sig.wipeSecretKeyLocked()
		}
	}()

	if cbErr := oqsrand.RandomBytesCustomAlgorithm(func(out []byte, n int) {
		if n > len(out) {
			n = len(out)
		}
		read, readErr := io.ReadFull(stream, out[:n])
		drawn += read
		if readErr != nil && streamErr == nil {
			streamErr = readErr
		}
	}); cbErr != nil {
		return nil, drawn, cbErr
	}
	// Runs before the randMutex unlock above: defers are LIFO, so the system RNG
	// is back in place while the lock still keeps signers out. Also covers a panic
	// from inside liboqs.
	defer restoreSystemRNG()

	pubKey, keyErr := sig.generateKeyPairUnlocked()
	if keyErr != nil {
		return nil, drawn, keyErr
	}
	if streamErr != nil {
		return nil, drawn, streamErr
	}
	return pubKey, drawn, nil
}

// wipeSecretKeyLocked destroys any secret key material generateKeyPairUnlocked
// may have written before an error was discovered further up the call stack.
// The caller must hold randMutex (it is only ever invoked from within
// GenerateKeyPairFromSeed's deferred cleanup). Leaving the key in place would
// mean a failed deterministic keygen still returns an error while the receiver
// silently holds a key generated from partly-zero randomness — usable by
// anything that later calls Sign or ExportSecretKey.
func (sig *Signature) wipeSecretKeyLocked() {
	if len(sig.secretKey) > 0 {
		MemCleanse(sig.secretKey)
	}
	sig.secretKey = nil
}

// restoreSystemRNG puts liboqs back on the system CSPRNG. Failing to restore it
// would leave the node signing with a deterministic RNG, which publishes the
// private key through repeated salts — halting is the lesser harm.
// The caller (GenerateKeyPairFromSeed) holds randMutex, which is what makes
// clearing the callback safe: no other goroutine can be inside liboqs.
func restoreSystemRNG() {
	if err := oqsrand.RandomBytesSwitchAlgorithm("system"); err != nil {
		logger.GetLogger().Fatal("cannot restore the system RNG after deterministic keygen; "+
			"continuing would sign with a predictable salt and leak the private key: ", err)
	}
	// Switching back is not enough: the package-level callback variable still
	// holds the closure, which captures the HKDF stream keyed by this key's seed.
	// Left in place it keeps that seed reachable — unfreed, and present in any
	// core dump — for the rest of the process lifetime, for a key that has
	// already been generated. Cleared only after the switch above succeeded, so
	// liboqs can never call into a nil callback.
	oqsrand.ClearCustomAlgorithm()
}

package common

import (
	crand "crypto/rand"
	"encoding/binary"
)

// RandomNonce returns a cryptographically random non-negative int64 suitable for
// use as a transaction nonce (WH-M2). Using a CSPRNG instead of math/rand makes
// nonces unpredictable, which mitigates front-running and replay guessing.
func RandomNonce() int64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		// crypto/rand should never fail; if it does, fail closed with 0 rather
		// than a predictable fallback.
		return 0
	}
	return int64(binary.BigEndian.Uint64(b[:]) >> 1)
}

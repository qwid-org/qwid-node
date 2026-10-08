package common

import (
	"crypto/rand"
	"time"
)

// Replay protection for signed RPC requests (S7-07). A signed request is
//
//	BytesToLenAndBytes(operation || payload) || guard || signature
//
// where guard = unix seconds (8 bytes) || random nonce (16 bytes) and the
// signature covers everything before it. The node accepts a guard only while
// it is fresh and only once, so a captured request - a TRAN, a CNCL, a VOTE -
// cannot be replayed.
const (
	RPCGuardLength = 8 + 16
	// RPCGuardMaxAge bounds, in seconds, how far a request's time may be from
	// the node's in either direction (wallet and node usually share a host).
	RPCGuardMaxAge int64 = 60
)

// NewRPCGuard returns a fresh guard for one request.
func NewRPCGuard() []byte {
	g := make([]byte, RPCGuardLength)
	copy(g[:8], GetByteInt64(time.Now().Unix()))
	if _, err := rand.Read(g[8:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return g
}

// RPCGuardTime is the request time a guard carries.
func RPCGuardTime(guard []byte) int64 {
	return GetInt64FromByte(guard[:8])
}

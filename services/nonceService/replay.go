package nonceServices

import (
	"sync"

	"github.com/qwid-org/qwid-node/common"
)

// Nonce replay guard (S2-08). A valid nonce for the next height could be
// replayed at will, and every copy re-saved the oracle and vote data, peeked
// 5000 pool transactions, built a merkle tree, checked and broadcast a
// candidate block. Each nonce is now acted on once. It is claimed only after
// its signature and producer authorization passed, so a forged message can't
// pre-empt the real nonce; entries for heights below the tip are dropped.
var (
	seenNoncesMu sync.Mutex
	seenNonces   = map[[32]byte]int64{}
)

func nonceAlreadyProcessed(hash [32]byte) bool {
	seenNoncesMu.Lock()
	defer seenNoncesMu.Unlock()
	_, ok := seenNonces[hash]
	return ok
}

// claimNonce marks a verified nonce as processed and reports whether this is
// its first sight.
func claimNonce(hash [32]byte, height, tip int64) bool {
	seenNoncesMu.Lock()
	defer seenNoncesMu.Unlock()
	for k, hgt := range seenNonces {
		if hgt <= tip-1 {
			delete(seenNonces, k)
		}
	}
	if _, ok := seenNonces[hash]; ok {
		return false
	}
	seenNonces[hash] = height
	return true
}

func resetSeenNonces() {
	seenNoncesMu.Lock()
	seenNonces = map[[32]byte]int64{}
	seenSenders = map[senderHeight]bool{}
	seenNoncesMu.Unlock()
}

type senderHeight struct {
	sender [common.AddressLength]byte
	height int64
}

// seenSenders: the validators whose nonce for a height was acted on.
var seenSenders = map[senderHeight]bool{}

// acceptNonceFrom decides, after a nonce's signature and its sender's
// authorization passed, whether to act on it (audit 2026-11-13). One nonce
// per validator and height: distinct nonces cost a validator nothing, and each
// made every receiver build a block candidate. Our own nonces are exempt -
// they are the once-a-second trigger of our production. A nonce sent from a
// clock more than MaxBlockForwardInTime away from ours is not acted on.
func acceptNonceFrom(sender, self common.Address, sendingTime, now, height, tip int64) bool {
	if sender.ByteValue == self.ByteValue {
		return true
	}
	if d := sendingTime - now; d > common.MaxBlockForwardInTime || -d > common.MaxBlockForwardInTime {
		return false
	}
	seenNoncesMu.Lock()
	defer seenNoncesMu.Unlock()
	for k := range seenSenders {
		if k.height <= tip-1 {
			delete(seenSenders, k)
		}
	}
	k := senderHeight{sender.ByteValue, height}
	if seenSenders[k] {
		return false
	}
	seenSenders[k] = true
	return true
}

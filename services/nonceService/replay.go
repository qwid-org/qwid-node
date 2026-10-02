package nonceServices

import "sync"

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
	seenNoncesMu.Unlock()
}

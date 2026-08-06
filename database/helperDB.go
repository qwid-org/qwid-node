package database

// LastContiguousHeight returns the highest height h for which key(h) exists,
// or -1 when height 0 is already missing. Heights are written contiguously from
// 0, so the boundary is found with an exponential probe followed by a binary
// search: O(log n) lookups instead of one per height.
//
// This matters far more than it looks. IsKey reads the value, so a linear scan
// over a chain of n blocks reads every snapshot ever written - at ~50k blocks a
// single scan took over ten minutes, and a rewind runs four of them. That is
// what made the node spend all its time inside ResetAccountsAndBlocksSync,
// holding the block lock and appearing frozen.
//
// On a read error the best height confirmed so far is returned alongside it, so
// callers keep the previous "return what we know" behaviour.
func LastContiguousHeight(db *BlockchainDB, key func(int64) []byte) (int64, error) {
	if db == nil {
		return -1, nil
	}
	exists := func(h int64) (bool, error) {
		return db.IsKey(key(h))
	}

	if ok, err := exists(0); err != nil {
		return -1, err
	} else if !ok {
		return -1, nil
	}

	// Exponential probe for a height that does NOT exist; lo always exists.
	lo, hi := int64(0), int64(1)
	for {
		ok, err := exists(hi)
		if err != nil {
			return lo, err
		}
		if !ok {
			break
		}
		lo = hi
		hi *= 2
	}

	// Binary search the boundary in (lo, hi]: lo exists, hi does not.
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		ok, err := exists(mid)
		if err != nil {
			return lo, err
		}
		if ok {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo, nil
}

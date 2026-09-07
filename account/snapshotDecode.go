package account

// snapshotDecode.go holds shared helpers for the state-snapshot decoders
// (QWID-2026-14). The snapshot format is fully attacker-controlled once an
// adversary can write the node's blockchain database or a storage/upgrade fault
// corrupts it, so every decoder must return a recoverable error rather than
// panic. These helpers bound the counts read from a snapshot before they are
// used to size allocations.

// maxSnapshotMapHint caps the preallocation hint passed to make() for a decoded
// map. A decoder still validates the count against the bytes actually present
// (a count larger than the remaining data is rejected), but the hint is capped
// independently so that even a count which passes the byte bound on a very large
// buffer cannot request an enormous single allocation up front. The loop that
// follows grows the map as needed, so a capped hint never loses data.
const maxSnapshotMapHint = 1 << 16

// safeMapHint converts a decoded (already non-negative) count into a bounded
// make() size hint. Callers reject negative counts as integrity errors before
// calling this; the extra guard here keeps a stray negative from ever reaching
// make(), which panics on a negative size.
func safeMapHint(count int64) int {
	if count <= 0 {
		return 0
	}
	if count > maxSnapshotMapHint {
		return maxSnapshotMapHint
	}
	return int(count)
}

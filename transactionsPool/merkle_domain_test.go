package transactionsPool

import (
	"bytes"
	"testing"
)

func rootOf(t *testing.T, data ...[]byte) []byte {
	t.Helper()
	nodes, err := NewMerkleTree(data)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("NewMerkleTree: %v, %d roots", err, len(nodes))
	}
	return nodes[0].Data
}

// S4-10: the transaction tree separates leaves from inner nodes and does not
// pad odd levels with a duplicate.
func TestMerkleTreeDomainSeparation(t *testing.T) {
	a, b, c := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)

	if bytes.Equal(rootOf(t, a, b, c), rootOf(t, a, b, c, c)) {
		t.Fatal("[a,b,c] and [a,b,c,c] share a root")
	}
	// An inner node's preimage presented as a leaf must not give the same hash.
	la, _ := NewMerkleNode(nil, nil, a)
	lb, _ := NewMerkleNode(nil, nil, b)
	asLeaf := append(append([]byte{}, la.Data...), lb.Data...)
	if bytes.Equal(rootOf(t, a, b), rootOf(t, asLeaf)) {
		t.Fatal("a leaf collides with an inner node")
	}
	if bytes.Equal(rootOf(t, a, b), rootOf(t, b, a)) {
		t.Fatal("the root ignores transaction order")
	}
	if !bytes.Equal(rootOf(t, a, b, c), rootOf(t, a, b, c)) {
		t.Fatal("the root is not deterministic")
	}
	// Building must not write into its inputs' hashes.
	before := append([]byte{}, la.Data...)
	if _, err := NewMerkleNode(la, lb, nil); err != nil || !bytes.Equal(la.Data, before) {
		t.Fatal("hashing an inner node modified its left child")
	}
}

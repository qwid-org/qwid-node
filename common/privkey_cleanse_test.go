package common

import "testing"

func TestPrivKeyCleanse(t *testing.T) {
	pk := &PrivKey{ByteValue: []byte{1, 2, 3, 4}}
	backing := pk.ByteValue // capture the backing array before Cleanse nils the field
	pk.Cleanse()
	for i, b := range backing {
		if b != 0 {
			t.Fatalf("backing byte %d = %d, want 0", i, b)
		}
	}
	if pk.ByteValue != nil {
		t.Fatal("ByteValue should be nil after Cleanse")
	}
}

func TestPrivKeyCleanseEmptyIsSafe(t *testing.T) {
	pk := &PrivKey{} // nil ByteValue must not panic
	pk.Cleanse()
	if pk.ByteValue != nil {
		t.Fatal("ByteValue should remain nil")
	}
}

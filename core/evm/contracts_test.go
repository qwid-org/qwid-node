package vm

import "testing"

func TestDataCopyReturnsCopy(t *testing.T) {
	in := []byte{1, 2, 3}
	out, err := (&dataCopy{}).Run(in)
	if err != nil {
		t.Fatal(err)
	}
	out[0] = 9
	if in[0] != 1 {
		t.Fatal("dataCopy returned a reference to the input, not a copy")
	}
}

func TestEcrecoverFailsLoud(t *testing.T) {
	// secp256k1 recovery is meaningless on this post-quantum chain; the
	// precompile must not return a deterministic garbage address.
	out, err := (&ecrecover{}).Run(make([]byte, 128))
	if err == nil && len(out) != 0 {
		t.Fatalf("ecrecover returned data (%x) instead of empty/err", out)
	}
}

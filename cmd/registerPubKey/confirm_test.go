package main

import (
	"bufio"
	"strings"
	"testing"
)

// S10-04: a local registration makes this node accept signatures the rest
// of the network rejects, and no rewind undoes it. The operator has to type
// an explicit confirmation naming the identity.
func TestLocalRegistrationNeedsTypedConfirmation(t *testing.T) {
	addr := "265b58a9f02dd71108e3a81e9312bb982db84426"
	want := "register locally 265b58a9"
	for _, answer := range []string{"\n", "y\n", "yes\n", "register locally\n", "register locally 00000000\n", ""} {
		if confirmLocalRegistration(bufio.NewReader(strings.NewReader(answer)), addr) {
			t.Fatalf("answer %q accepted", answer)
		}
	}
	if !confirmLocalRegistration(bufio.NewReader(strings.NewReader(want+"\n")), addr) {
		t.Fatal("the exact confirmation was refused")
	}
}

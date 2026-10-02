package main

import "testing"

// S10-03: the load tool spends the node wallet's funds. It needs an explicit
// recipient, a finite count and a typed testnet acknowledgement.
func TestParseLoadArgs(t *testing.T) {
	to := "265b58a9f02dd71108e3a81e9312bb982db84426"
	if _, err := parseLoadArgs([]string{"-to", to, "-count", "5"}); err == nil {
		t.Fatal("ran without the testnet acknowledgement")
	}
	if _, err := parseLoadArgs([]string{"-testnet"}); err == nil {
		t.Fatal("ran without a recipient")
	}
	if _, err := parseLoadArgs([]string{"-testnet", "-to", "zz"}); err == nil {
		t.Fatal("accepted a malformed recipient")
	}
	if _, err := parseLoadArgs([]string{"-testnet", "-to", to, "-count", "0"}); err == nil {
		t.Fatal("accepted an unbounded run")
	}
	cfg, err := parseLoadArgs([]string{"-testnet", "-to", to, "-count", "7", "-workers", "2", "-node", "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.count != 7 || cfg.workers != 2 || cfg.node != "10.0.0.5" || cfg.recipient.GetHex() != to {
		t.Fatalf("cfg = %+v", cfg)
	}
}

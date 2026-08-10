package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/core/stateDB"
	"github.com/qwid-org/qwid-node/core/types"
)

// IsTokenToRegister decides whether deployed bytecode is treated as a token —
// which is what makes it tradeable on the protocol DEX and gives it an entry in
// the token registry. It answers that by looking for five ERC-20-ish function
// selectors in the code, so both directions matter: missing one selector must
// keep a contract out, and finding all five must let it in.

// tokenSelectors is the exact set IsTokenToRegister looks for.
func tokenSelectors() [][]byte {
	return [][]byte{
		stateDB.NameFunc,
		stateDB.BalanceOfFunc,
		stateDB.TransferFunc,
		stateDB.SymbolFunc,
		stateDB.DecimalsFunc,
	}
}

// codeWith concatenates the given selectors with filler around them, the way a
// real compiled dispatcher embeds them.
func codeWith(sels [][]byte) []byte {
	code := []byte{0x60, 0x80, 0x60, 0x40, 0x52} // typical prologue filler
	for _, s := range sels {
		code = append(code, 0x63) // PUSH4
		code = append(code, s...)
		code = append(code, 0x14, 0x57) // EQ, JUMPI
	}
	return code
}

func TestContractWithEveryTokenSelectorRegisters(t *testing.T) {
	if !IsTokenToRegister(codeWith(tokenSelectors())) {
		t.Fatal("code containing all five selectors was not recognised as a token")
	}
}

// Dropping any single selector must keep the contract out of the registry. A
// contract that cannot report its decimals or move a balance would otherwise be
// listed as tradeable and priced against on the DEX.
func TestMissingAnySelectorPreventsRegistration(t *testing.T) {
	names := []string{"name", "balanceOf", "transfer", "symbol", "decimals"}
	all := tokenSelectors()

	for skip := range all {
		subset := make([][]byte, 0, len(all)-1)
		for i, s := range all {
			if i != skip {
				subset = append(subset, s)
			}
		}
		if IsTokenToRegister(codeWith(subset)) {
			t.Errorf("code without %s() was still registered as a token", names[skip])
		}
	}
}

func TestEmptyAndTrivialCodeIsNotAToken(t *testing.T) {
	for name, code := range map[string][]byte{
		"nil":          nil,
		"empty":        {},
		"single byte":  {0x00},
		"random bytes": {0xde, 0xad, 0xbe, 0xef, 0x11, 0x22},
	} {
		if IsTokenToRegister(code) {
			t.Errorf("%s was registered as a token", name)
		}
	}
}

// The selectors are matched as byte substrings, so a selector split across the
// code must not count. This is what stops incidental byte sequences from
// promoting a non-token contract.
func TestSelectorMustAppearContiguously(t *testing.T) {
	all := tokenSelectors()
	code := codeWith(all[:4])

	// Append the fifth selector with a byte inserted in the middle.
	last := all[4]
	code = append(code, last[:2]...)
	code = append(code, 0xff)
	code = append(code, last[2:]...)

	if IsTokenToRegister(code) {
		t.Fatal("a selector broken by an inserted byte still counted as present")
	}
}

// ------------------------------------------------------------------ logging

func TestFormatEVMLogsIsEmptyWithoutLogs(t *testing.T) {
	if got := formatEVMLogs(nil); got != "" {
		t.Errorf("nil logs formatted to %q, want empty", got)
	}
	if got := formatEVMLogs([]*types.Log{}); got != "" {
		t.Errorf("no logs formatted to %q, want empty", got)
	}
}

func TestFormatEVMLogsRendersEntries(t *testing.T) {
	out := formatEVMLogs([]*types.Log{{Data: []byte{1, 2, 3}}})

	if out == "" {
		t.Fatal("a log entry produced no output")
	}
	if len(out) < len("\nEVM Logs:\n") || out[:11] != "\nEVM Logs:\n" {
		t.Fatalf("output does not carry the expected header: %q", out)
	}
}

package handlers

import (
	"strings"
	"testing"
)

// TestSolImportDetection verifies WH-C1: import statements are detected and
// ordinary contracts are not falsely rejected.
func TestSolImportDetection(t *testing.T) {
	rejects := []string{
		`import "/etc/passwd";`,
		"pragma solidity ^0.8.0;\nimport \"./other.sol\";",
		`  import {Foo} from "bar";`,
	}
	for _, c := range rejects {
		if !solImportRE.MatchString(c) {
			t.Fatalf("expected import to be detected in: %q", c)
		}
	}
	allows := []string{
		"pragma solidity ^0.8.0;\ncontract C { uint x; }",
		"// this mentions the word import in a comment\ncontract C {}",
	}
	for _, c := range allows {
		if solImportRE.MatchString(c) {
			t.Fatalf("did not expect import match in: %q", c)
		}
	}
}

// TestSanitizeSolcError verifies WH-H1: the temp directory path is stripped from
// compiler output.
func TestSanitizeSolcError(t *testing.T) {
	tmpDir := "/tmp/qwid-solc-12345"
	raw := tmpDir + "/contract.sol:3:1: Error: something bad\n" + tmpDir + " referenced"
	got := sanitizeSolcError(raw, tmpDir)
	if strings.Contains(got, tmpDir) {
		t.Fatalf("temp dir path leaked in sanitized output: %q", got)
	}
	if !strings.Contains(got, "contract.sol") {
		t.Fatalf("expected contract.sol to remain: %q", got)
	}
}

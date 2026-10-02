package main

import (
	"errors"
	"testing"
)

func feed(answers ...string) func() ([]byte, error) {
	return func() ([]byte, error) {
		if len(answers) == 0 {
			return nil, errors.New("no more input")
		}
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
}

// S10-02: the generator that creates validator wallets enforces the same
// minimum as every other wallet-creating flow, and has the password typed
// twice.
func TestReadNewPasswordEnforcesMinimumAndConfirmation(t *testing.T) {
	if _, err := readNewPassword(feed("short", "short", "", "", "abc", "abc")); err == nil {
		t.Fatal("a too-short password was accepted")
	}
	if _, err := readNewPassword(feed("longenough1", "different22", "longenough1", "typo", "longenough1", "x")); err == nil {
		t.Fatal("a password not confirmed identically was accepted")
	}
	pw, err := readNewPassword(feed("short", "short", "longenough1", "longenough1"))
	if err != nil || string(pw) != "longenough1" {
		t.Fatalf("got %q, %v", pw, err)
	}
}

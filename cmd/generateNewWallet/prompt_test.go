package main

import (
	"strings"
	"testing"
)

func TestConfirmPositionsAreDistinctAndInRange(t *testing.T) {
	pos := confirmPositions([8]byte{1, 2, 3, 4, 5, 6, 7, 8}, 24)
	if len(pos) != 3 {
		t.Fatalf("liczba pozycji = %d, oczekiwano 3", len(pos))
	}
	seen := map[int]bool{}
	for _, p := range pos {
		if p < 1 || p > 24 {
			t.Fatalf("pozycja %d poza zakresem 1..24", p)
		}
		if seen[p] {
			t.Fatalf("pozycja %d powtórzona", p)
		}
		seen[p] = true
	}
}

func TestCheckConfirmationAcceptsCorrectWords(t *testing.T) {
	mnemonic := strings.Join(strings.Fields(strings.Repeat("abandon ", 23)+"art"), " ")
	words := strings.Fields(mnemonic)
	positions := []int{1, 12, 24}
	answers := []string{words[0], words[11], words[23]}

	if err := checkConfirmation(mnemonic, positions, answers); err != nil {
		t.Fatalf("poprawne słowa odrzucone: %v", err)
	}
}

func TestCheckConfirmationRejectsWrongWord(t *testing.T) {
	mnemonic := strings.Join(strings.Fields(strings.Repeat("abandon ", 23)+"art"), " ")
	positions := []int{1, 12, 24}
	answers := []string{"abandon", "abandon", "abandon"} // pozycja 24 to "art"

	err := checkConfirmation(mnemonic, positions, answers)
	if err == nil {
		t.Fatal("oczekiwano błędu dla błędnego słowa")
	}
	if !strings.Contains(err.Error(), "24") {
		t.Fatalf("komunikat %q nie wskazuje błędnej pozycji", err.Error())
	}
}

func TestCheckConfirmationIsCaseAndSpaceInsensitive(t *testing.T) {
	mnemonic := strings.Join(strings.Fields(strings.Repeat("abandon ", 23)+"art"), " ")
	if err := checkConfirmation(mnemonic, []int{24}, []string{"  ART "}); err != nil {
		t.Fatalf("odrzucono poprawne słowo z inną wielkością liter i spacjami: %v", err)
	}
}

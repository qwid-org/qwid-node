package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestConfirmOverwriteAllowsFreeWalletNumber: a free number must not prompt.
func TestConfirmOverwriteAllowsFreeWalletNumber(t *testing.T) {
	dir := t.TempDir()
	confirmed, err := confirmOverwriteIfExists(bufio.NewReader(strings.NewReader("")), walletFilePath(dir, 7), 7)
	if err != nil {
		t.Fatalf("wolny numer portfela odrzucony: %v", err)
	}
	if confirmed {
		t.Fatal("zgłoszono potwierdzenie nadpisania dla nieistniejącego pliku")
	}
}

// TestConfirmOverwriteRefusesOccupiedWalletNumber is the C1 regression: the
// wallet file for the chosen number exists and the operator does NOT type the
// confirmation phrase. Every one of these answers must abort — especially "y",
// "yes" and a bare Enter, which are what a panicking operator running the
// restore mode types by reflex.
func TestConfirmOverwriteRefusesOccupiedWalletNumber(t *testing.T) {
	for _, answer := range []string{"\n", "y\n", "yes\n", "tak\n", "nadpisz\n", "nadpisz portfel 1\n", ""} {
		dir := t.TempDir()
		file := walletFilePath(dir, 0)
		if err := os.WriteFile(file, []byte(`{"wallet_number":0}`), 0600); err != nil {
			t.Fatal(err)
		}
		confirmed, err := confirmOverwriteIfExists(bufio.NewReader(strings.NewReader(answer)), file, 0)
		if err == nil {
			t.Fatalf("odpowiedź %q nadpisała istniejący portfel 0", answer)
		}
		if confirmed {
			t.Fatalf("odpowiedź %q zgłoszona jako potwierdzenie", answer)
		}
		// The file must still be there, untouched: refusing is only useful if
		// nothing was written on the way to the refusal.
		if data, rerr := os.ReadFile(file); rerr != nil || string(data) != `{"wallet_number":0}` {
			t.Fatalf("istniejący plik portfela został naruszony (%v, %q)", rerr, string(data))
		}
	}
}

// TestConfirmOverwriteAcceptsExactPhrase: the escape hatch has to actually work,
// otherwise a legitimate overwrite becomes impossible.
func TestConfirmOverwriteAcceptsExactPhrase(t *testing.T) {
	dir := t.TempDir()
	file := walletFilePath(dir, 12)
	if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, answer := range []string{"nadpisz portfel 12\n", "  NADPISZ   Portfel 12  \n"} {
		confirmed, err := confirmOverwriteIfExists(bufio.NewReader(strings.NewReader(answer)), file, 12)
		if err != nil {
			t.Fatalf("odrzucono poprawne potwierdzenie %q: %v", answer, err)
		}
		if !confirmed {
			t.Fatalf("potwierdzenie %q nie zostało zgłoszone jako potwierdzone", answer)
		}
	}
}

// TestCheckOverwriteConfirmationNamesWalletNumber guards the "names what will be
// destroyed" requirement: the phrase for wallet 0 must not confirm wallet 1.
func TestCheckOverwriteConfirmationNamesWalletNumber(t *testing.T) {
	if err := checkOverwriteConfirmation("nadpisz portfel 0", 1); err == nil {
		t.Fatal("potwierdzenie dla portfela 0 zaakceptowane dla portfela 1")
	}
	if err := checkOverwriteConfirmation("nadpisz portfel 1", 1); err != nil {
		t.Fatalf("odrzucono własne potwierdzenie: %v", err)
	}
}

// TestWalletFilePathMatchesStoreJSON pins the guard's path to the one StoreJSON
// writes (filepath.Join(HomePath, "wallet<N>.json")). If they ever diverge the
// guard would check a file that is not the one about to be destroyed.
func TestWalletFilePathMatchesStoreJSON(t *testing.T) {
	got := walletFilePath("/home/op/.qwid/wallet/3", 3)
	want := filepath.Join("/home/op/.qwid/wallet/3", "wallet3.json")
	if got != want {
		t.Fatalf("walletFilePath = %q, oczekiwano %q", got, want)
	}
}

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

// TestConfirmPositionsTerminates guards against the update-rule fixed point a
// reviewer found in the original `n = n/wordCount + 1` step: it settles at
// n==1 (since 1/24+1==1), after which p is deterministically 1%24+1==2 on
// every iteration, so confirmPositions never returns once position 2 is
// already chosen. All-zero and the next few small seeds hit that fixed point
// under the old formula; each is run in a goroutine with a timeout so the
// test fails instead of hanging forever if the bug ever comes back.
func TestConfirmPositionsTerminates(t *testing.T) {
	seeds := [][8]byte{
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 1},
		{0, 0, 0, 0, 0, 0, 0, 2},
	}
	for _, seed := range seeds {
		seed := seed
		done := make(chan []int, 1)
		go func() {
			done <- confirmPositions(seed, 24)
		}()
		select {
		case pos := <-done:
			if len(pos) != 3 {
				t.Fatalf("seed %v: liczba pozycji = %d, oczekiwano 3", seed, len(pos))
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("confirmPositions(%v, 24) nie zakończyło się w 2s (zawieszenie)", seed)
		}
	}
}

// TestConfirmPositionsVariesWithSeed guards against a stub that ignores its
// seed entirely (e.g. always returning []int{1,2,3}), which would otherwise
// pass every other test in this file despite contradicting the doc comment's
// promise that the choice is unpredictable.
func TestConfirmPositionsVariesWithSeed(t *testing.T) {
	seeds := [][8]byte{
		{1, 2, 3, 4, 5, 6, 7, 8},
		{9, 8, 7, 6, 5, 4, 3, 2},
		{0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0},
		{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
	}
	first := confirmPositions(seeds[0], 24)
	allSame := true
	for _, seed := range seeds[1:] {
		pos := confirmPositions(seed, 24)
		if !equalIntSlices(pos, first) {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatalf("confirmPositions zwróciło te same pozycje %v dla wszystkich testowanych ziaren; funkcja wygląda na to, że ignoruje ziarno", first)
	}
}

func equalIntSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

package qtwidgets

import (
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/wallet"
)

// TestMatchesOverwriteConfirmationRejectsCasualAnswers: the GUI restore now
// writes the wallet file, so the confirmation in front of it must not be
// something a panicking user clicks through. Only the exact phrase, naming the
// wallet number, may pass.
func TestMatchesOverwriteConfirmationRejectsCasualAnswers(t *testing.T) {
	for _, answer := range []string{"", "y", "yes", "Yes", "ok", "overwrite", "overwrite wallet", "overwrite wallet 1"} {
		if matchesOverwriteConfirmation(answer, 0) {
			t.Fatalf("odpowiedź %q potwierdziła nadpisanie portfela 0", answer)
		}
	}
}

func TestMatchesOverwriteConfirmationAcceptsExactPhrase(t *testing.T) {
	for _, answer := range []string{"overwrite wallet 0", "  OVERWRITE   Wallet 0 "} {
		if !matchesOverwriteConfirmation(answer, 0) {
			t.Fatalf("odrzucono poprawne potwierdzenie %q", answer)
		}
	}
	if !matchesOverwriteConfirmation("overwrite wallet 7", 7) {
		t.Fatal("odrzucono poprawne potwierdzenie dla portfela 7")
	}
	if matchesOverwriteConfirmation("overwrite wallet 7", 70) {
		t.Fatal("potwierdzenie dla portfela 7 zaakceptowane dla portfela 70")
	}
}

// TestWalletFilePathOfMatchesStoreJSON pins the path shown in the confirmation
// dialog to the one StoreJSON actually writes; a mismatch would name the wrong
// file in a dialog whose whole job is telling the user what is about to be
// destroyed.
func TestWalletFilePathOfMatchesStoreJSON(t *testing.T) {
	w := wallet.EmptyWallet(3, "Falcon-512", "MAYO-5")
	w.HomePath = t.TempDir()
	got := walletFilePathOf(&w)
	want := filepath.Join(w.HomePath, "wallet3.json")
	if got != want {
		t.Fatalf("walletFilePathOf = %q, oczekiwano %q", got, want)
	}
}

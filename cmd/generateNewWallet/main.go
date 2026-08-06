package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/wallet"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	// Get the current user
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error getting current user:", err)
		return
	}

	fmt.Println("Current user:", currentUser.Username)
	var input string
	fmt.Print("Enter wallet number (0-255): ")
	_, err = fmt.Scanln(&input)
	if err != nil {
		fmt.Println("Error reading input:", err)
		return
	}
	walletNumber, err := strconv.Atoi(input)
	if (err != nil) || (0 > walletNumber) || (walletNumber > 255) {
		logger.GetLogger().Fatalf("wallet number should be integer from 0 to 255. Not %d", walletNumber)
	}
	fmt.Print("Enter password: ")

	password, err := terminal.ReadPassword(0)
	if err != nil {
		logger.GetLogger().Fatal(err)
	}

	w := wallet.EmptyWallet(uint8(walletNumber), common.SigName(), common.SigName2())
	walletFile := walletFilePath(w.HomePath, walletNumber)

	reader := bufio.NewReader(os.Stdin)

	// Refuse to overwrite an occupied wallet number without an explicit, typed
	// confirmation. This runs before ANY mode is chosen, so it protects the
	// restore path too — which is the dangerous one: it is run by an operator
	// who has just lost a wallet, the first prompt asks for a wallet number,
	// and "0" is the natural answer. StoreJSON is an unconditional
	// os.WriteFile, so without this guard one keystroke silently destroys the
	// only backup of a pre-existing wallet (a wallet created before recovery
	// phrases existed has NO phrase — its encrypted file is the sole copy of
	// its keys, and nothing can rebuild it).
	overwriteConfirmed, err := confirmOverwriteIfExists(reader, walletFile, walletNumber)
	if err != nil {
		logger.GetLogger().Fatalf("%v — nie zapisano żadnego pliku", err)
	}

	fmt.Print("\n[1] utwórz nowy portfel  [2] odtwórz z frazy 24 słów\nWybór [1]: ")
	mode, _ := reader.ReadString('\n')
	mode = strings.TrimSpace(mode)

	var mnemonic []byte
	if mode == "2" {
		fmt.Print("Wpisz frazę (24 słowa oddzielone spacjami): ")
		// Read without echo: the phrase owns every key of the wallet, so echoing
		// it would leave it in terminal scrollback, tmux/screen logs and any
		// recording of the session. ReadPassword reads fd 0 directly, which is
		// also why the password above is read the same way. A typo stays
		// invisible, but SeedFromMnemonic's checksum check below catches it.
		line, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			logger.GetLogger().Fatal(err)
		}
		fmt.Println()
		mnemonic = []byte(strings.TrimSpace(string(line)))
		wallet.ZeroBytes(line)
		if _, err := wallet.SeedFromMnemonic(mnemonic); err != nil {
			logger.GetLogger().Fatal(err)
		}
	} else {
		mnemonic, err = wallet.NewMnemonic24()
		if err != nil {
			logger.GetLogger().Fatal(err)
		}
		fmt.Println("\n================ FRAZA ODZYSKIWANIA ================")
		fmt.Println(string(mnemonic))
		fmt.Println("====================================================")
		fmt.Println("Zapisz ją teraz. Nie da się jej odzyskać z klucza,")
		fmt.Println("a bez niej ani bez pliku portfela środki przepadną.")

		positions, err := randomConfirmPositions(wallet.MnemonicWordCount)
		if err != nil {
			logger.GetLogger().Fatal(err)
		}

		// A typo here must not cost the operator the phrase they just wrote
		// down: the phrase is shown once, above, and is not repeated on retry
		// (a wrong answer here creates no wallet, but the very next run would
		// mint a brand-new phrase, making the one just written down worthless).
		// Three attempts catches fat-fingering without turning the check into
		// a formality.
		const maxConfirmAttempts = 3
		confirmed := false
		for attempt := 1; attempt <= maxConfirmAttempts; attempt++ {
			answers := make([]string, len(positions))
			for i, p := range positions {
				fmt.Printf("Podaj słowo numer %d: ", p)
				line, err := reader.ReadString('\n')
				if err != nil {
					logger.GetLogger().Fatal(err)
				}
				answers[i] = line
			}
			if err := checkConfirmation(string(mnemonic), positions, answers); err != nil {
				fmt.Printf("Potwierdzenie nie powiodło się (próba %d/%d): %v\n", attempt, maxConfirmAttempts, err)
				continue
			}
			confirmed = true
			break
		}
		if !confirmed {
			logger.GetLogger().Fatalf("potwierdzenie frazy nie powiodło się po %d próbach", maxConfirmAttempts)
		}
	}
	defer wallet.ZeroBytes(mnemonic)

	w.SetPassword(string(password))
	w.Iv = wallet.GenerateNewIv()

	if err := w.SetMnemonic(mnemonic); err != nil {
		logger.GetLogger().Fatal(err)
	}

	// A derivation failure here must stop everything: the operator has already
	// been shown (or has already typed in) the recovery phrase and believes it
	// backs a real wallet. Falling through with a zero-value account would
	// silently write a wallet file for the zero address instead. Fatal exits
	// non-zero before any file is created.
	acc, err := wallet.GenerateNewAccountFromSeed(w, w.SigName, true)
	if err != nil {
		logger.GetLogger().Fatalf("Can not create wallet, no file was written. Error %v", err)
	}
	w.MainAddress = acc.Address
	acc.PublicKey.MainAddress = w.MainAddress
	w.Account1 = acc
	copy(w.Account1.EncryptedSecretKey, acc.EncryptedSecretKey)

	acc, err = wallet.GenerateNewAccountFromSeed(w, w.SigName2, false)
	if err != nil {
		logger.GetLogger().Fatalf("Can not create wallet, no file was written. Error %v", err)
	}

	w.Account2 = acc
	copy(w.Account2.EncryptedSecretKey, acc.EncryptedSecretKey)

	folderPath := w.HomePath
	err = os.MkdirAll(folderPath, 0700) // CW-H3: owner-only; matches StoreJSON's 0700 (MkdirAll won't chmod an existing dir)
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	fileInfo, err := os.Stat(folderPath)
	if err != nil {
		fmt.Println("Error getting folder info:", err)
		return
	}
	// Get the folder permissions
	permissions := fileInfo.Mode().Perm()
	fmt.Printf("Folder permissions: %v\n", permissions)
	// Check if the current user has read, write, and execute permissions
	hasReadPermission := permissions&0400 != 0
	hasWritePermission := permissions&0200 != 0
	hasExecutePermission := permissions&0100 != 0
	fmt.Printf("Read permission: %v\n", hasReadPermission)
	fmt.Printf("Write permission: %v\n", hasWritePermission)
	fmt.Printf("Execute permission: %v\n", hasExecutePermission)

	// Re-check right before the write. The guard above ran several prompts ago;
	// this closes the window in which the file appeared in the meantime (another
	// generator run, a restored backup) and would be destroyed by a confirmation
	// that was never given for it.
	if !overwriteConfirmed {
		if _, statErr := os.Stat(walletFile); statErr == nil {
			logger.GetLogger().Fatalf("plik %s pojawił się w trakcie tworzenia portfela, a nadpisanie nie zostało potwierdzone — nie zapisano niczego", walletFile)
		}
	}

	err = w.StoreJSON()
	if err != nil {
		logger.GetLogger().Println(err)
		return
	}

	fmt.Printf("\nAdres portfela: %s\n", w.MainAddress.GetHex())
}

// walletFilePath is the file StoreJSON writes for this wallet number. Kept next
// to the overwrite guard so the guard can never end up checking a different path
// than the one that is about to be written.
func walletFilePath(homePath string, walletNumber int) string {
	return filepath.Join(homePath, "wallet"+strconv.Itoa(walletNumber)+".json")
}

// overwriteConfirmationPhrase is what the operator must type, verbatim, to
// destroy an existing wallet file. It deliberately names the wallet number: a
// bare "y" (or a reflex "yes") is exactly what a panicking operator types
// without reading, and the number is the thing they are most likely to have got
// wrong in the first place.
func overwriteConfirmationPhrase(walletNumber int) string {
	return fmt.Sprintf("nadpisz portfel %d", walletNumber)
}

// checkOverwriteConfirmation reports whether answer is the exact confirmation
// phrase for walletNumber. Surrounding whitespace and letter case are ignored;
// nothing else is.
func checkOverwriteConfirmation(answer string, walletNumber int) error {
	want := overwriteConfirmationPhrase(walletNumber)
	got := strings.Join(strings.Fields(strings.ToLower(answer)), " ")
	if got != want {
		return fmt.Errorf("nie potwierdzono nadpisania portfela %d (oczekiwano dokładnie %q, podano %q)", walletNumber, want, answer)
	}
	return nil
}

// confirmOverwriteIfExists refuses to continue when walletFile already exists,
// unless the operator types the confirmation phrase for walletNumber. It
// returns whether an overwrite was confirmed. A missing file needs no
// confirmation; a stat error that is not "does not exist" is treated as a
// refusal, because we cannot then prove the number is free.
func confirmOverwriteIfExists(in *bufio.Reader, walletFile string, walletNumber int) (bool, error) {
	if _, err := os.Stat(walletFile); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("nie można sprawdzić, czy portfel %d jest zajęty (%s): %v", walletNumber, walletFile, err)
	}

	fmt.Printf("\n!!! UWAGA: portfel numer %d JUŻ ISTNIEJE !!!\n", walletNumber)
	fmt.Printf("Plik: %s\n", walletFile)
	fmt.Println("Kontynuacja NADPISZE ten plik. Klucze, które są w nim zapisane,")
	fmt.Println("zostaną zniszczone bezpowrotnie — jeśli ten portfel powstał przed")
	fmt.Println("wprowadzeniem fraz odzyskiwania, ten plik jest jedyną kopią jego")
	fmt.Println("kluczy i nic ich potem nie odtworzy. Środki na nim przepadną.")
	fmt.Println("Jeśli chciałeś tylko odtworzyć portfel z frazy, użyj WOLNEGO numeru.")
	fmt.Printf("\nAby nadpisać, wpisz dokładnie: %s\nW przeciwnym razie naciśnij Enter, aby przerwać.\n> ", overwriteConfirmationPhrase(walletNumber))

	answer, err := in.ReadString('\n')
	if err != nil && answer == "" {
		return false, fmt.Errorf("nie potwierdzono nadpisania portfela %d (%s): %v", walletNumber, walletFile, err)
	}
	if err := checkOverwriteConfirmation(answer, walletNumber); err != nil {
		return false, err
	}
	fmt.Printf("Potwierdzono nadpisanie portfela %d (%s).\n", walletNumber, walletFile)
	return true, nil
}

// confirmWordCount is how many words the operator must type back before the
// wallet is created. Three is enough to catch "I'll write it down later" without
// making the prompt tedious.
const confirmWordCount = 3

// confirmPositions picks distinct 1-based word positions to ask about, derived
// from seed64 so the choice is unpredictable but the function stays testable.
func confirmPositions(seed64 [8]byte, wordCount int) []int {
	n := binary.BigEndian.Uint64(seed64[:])
	chosen := map[int]bool{}
	out := make([]int, 0, confirmWordCount)
	for len(out) < confirmWordCount {
		p := int(n%uint64(wordCount)) + 1
		// Full-period 64-bit LCG (Hull-Dobell: odd increment, multiplier ≡ 1 mod 4;
		// this is the multiplier used by PCG/Numerical Recipes). n advances
		// unconditionally on every iteration, collision or not, so it can never
		// settle on a fixed point and spin forever — unlike the previous
		// `n = n/wordCount + 1`, which has a fixed point at n==1 (1/wordCount+1==1)
		// and can loop forever once it lands there and p is already chosen.
		n = n*6364136223846793005 + 1
		if chosen[p] {
			continue
		}
		chosen[p] = true
		out = append(out, p)
	}
	return out
}

// randomConfirmPositions is confirmPositions seeded from the system CSPRNG.
func randomConfirmPositions(wordCount int) ([]int, error) {
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return confirmPositions(seed, wordCount), nil
}

// checkConfirmation verifies the operator typed back the right words. Comparison
// ignores surrounding space and letter case; BIP39 words are lowercase ASCII.
func checkConfirmation(mnemonic string, positions []int, answers []string) error {
	words := strings.Fields(mnemonic)
	if len(positions) != len(answers) {
		return fmt.Errorf("oczekiwano %d odpowiedzi, podano %d", len(positions), len(answers))
	}
	for i, p := range positions {
		if p < 1 || p > len(words) {
			return fmt.Errorf("pozycja %d poza zakresem", p)
		}
		got := strings.ToLower(strings.TrimSpace(answers[i]))
		if got != words[p-1] {
			return fmt.Errorf("słowo na pozycji %d nie zgadza się", p)
		}
	}
	return nil
}

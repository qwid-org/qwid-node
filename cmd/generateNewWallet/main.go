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

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\n[1] utwórz nowy portfel  [2] odtwórz z frazy 24 słów\nWybór [1]: ")
	mode, _ := reader.ReadString('\n')
	mode = strings.TrimSpace(mode)

	var mnemonic []byte
	if mode == "2" {
		fmt.Print("Wpisz frazę (24 słowa oddzielone spacjami): ")
		line, err := reader.ReadString('\n')
		if err != nil {
			logger.GetLogger().Fatal(err)
		}
		mnemonic = []byte(strings.TrimSpace(line))
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
			logger.GetLogger().Fatal("potwierdzenie frazy nie powiodło się: ", err)
		}
	}
	defer wallet.ZeroBytes(mnemonic)

	w := wallet.EmptyWallet(uint8(walletNumber), common.SigName(), common.SigName2())
	w.SetPassword(string(password))
	w.Iv = wallet.GenerateNewIv()

	if err := w.SetMnemonic(mnemonic); err != nil {
		logger.GetLogger().Fatal(err)
	}

	acc, err := wallet.GenerateNewAccountFromSeed(w, w.SigName, true)
	if err != nil {
		logger.GetLogger().Printf("Can not create wallet. Error %v", err)
	}
	w.MainAddress = acc.Address
	acc.PublicKey.MainAddress = w.MainAddress
	w.Account1 = acc
	copy(w.Account1.EncryptedSecretKey, acc.EncryptedSecretKey)

	acc, err = wallet.GenerateNewAccountFromSeed(w, w.SigName2, false)
	if err != nil {
		logger.GetLogger().Printf("Can not create wallet. Error %v", err)
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

	err = w.StoreJSON()
	if err != nil {
		logger.GetLogger().Println(err)
		return
	}

	fmt.Printf("\nAdres portfela: %s\n", w.MainAddress.GetHex())
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
		n = n/uint64(wordCount) + 1
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

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/tcpip"
	"github.com/qwid-org/qwid-node/wallet"
	"golang.org/x/crypto/ssh/terminal"
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
	password, err := readNewPassword(func() ([]byte, error) {
		b, err := terminal.ReadPassword(0)
		fmt.Println()
		return b, err
	})
	if err != nil {
		logger.GetLogger().Fatal(err)
	}

	// Keys and the address must be those of the schemes the chain runs NOW.
	// Ask the node (argument 1, default 127.0.0.1); without one, fall back to
	// the built-in defaults - right only for a chain that never changed its
	// schemes, e.g. when preparing a genesis.
	nodeIP := "127.0.0.1"
	if len(os.Args) > 1 {
		nodeIP = os.Args[1]
	}
	defaultSig, defaultSig2 := common.SigName(), common.SigName2()
	sigName, sigName2, primaryPaused, schemeErr := chainSchemes(nodeIP)
	online := schemeErr == nil
	if online {
		fmt.Printf("Chain signature schemes: %s (primary%s) / %s\n", sigName, map[bool]string{true: ", PAUSED", false: ""}[primaryPaused], sigName2)
	} else {
		sigName, sigName2 = defaultSig, defaultSig2
		fmt.Printf("WARNING: %v\nUsing the default schemes %s / %s. That is right only for a chain that never changed\n"+
			"its schemes (e.g. preparing a genesis); otherwise run this with a reachable node:\n"+
			"  go run cmd/generateNewWallet/main.go <node_ip>\n", schemeErr, sigName, sigName2)
	}

	w := wallet.EmptyWallet(uint8(walletNumber), sigName, sigName2)
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
		logger.GetLogger().Fatalf("%v — no file was written", err)
	}

	fmt.Print("\n[1] create a new wallet  [2] restore from a 24-word phrase\nChoice [1]: ")
	mode, _ := reader.ReadString('\n')
	mode = strings.TrimSpace(mode)

	var mnemonic []byte
	if mode == "2" {
		fmt.Print("Enter the phrase (24 words separated by spaces): ")
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
		fmt.Println("\n================ RECOVERY PHRASE ================")
		fmt.Println(string(mnemonic))
		fmt.Println("=================================================")
		fmt.Println("Write it down now. It cannot be recovered from the key,")
		fmt.Println("and without it or the wallet file the funds are lost.")

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
				fmt.Printf("Enter word number %d: ", p)
				line, err := reader.ReadString('\n')
				if err != nil {
					logger.GetLogger().Fatal(err)
				}
				answers[i] = line
			}
			if err := checkConfirmation(string(mnemonic), positions, answers); err != nil {
				fmt.Printf("Confirmation failed (attempt %d/%d): %v\n", attempt, maxConfirmAttempts, err)
				continue
			}
			confirmed = true
			break
		}
		if !confirmed {
			logger.GetLogger().Fatalf("phrase confirmation failed after %d attempts", maxConfirmAttempts)
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
	acc1, err := wallet.GenerateNewAccountFromSeed(w, w.SigName, true)
	if err != nil {
		logger.GetLogger().Fatalf("Can not create wallet, no file was written. Error %v", err)
	}
	acc2, err := wallet.GenerateNewAccountFromSeed(w, w.SigName2, false)
	if err != nil {
		logger.GetLogger().Fatalf("Can not create wallet, no file was written. Error %v", err)
	}
	w.Account1 = acc1
	copy(w.Account1.EncryptedSecretKey, acc1.EncryptedSecretKey)
	w.Account2 = acc2
	copy(w.Account2.EncryptedSecretKey, acc2.EncryptedSecretKey)

	if mode == "2" {
		restoreIdentity(&w, online, primaryPaused, defaultSig, defaultSig2)
	} else {
		// A new identity takes its address from the LIVE scheme's key: while the
		// primary is paused, an address from the primary key could open the
		// account but never add its spare (wallet.SetMainAddressFromLiveScheme).
		w.SetMainAddressFromLiveScheme(online && primaryPaused)
	}
	fmt.Println("Wallet address (identity):", w.MainAddress.GetHex())

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
			logger.GetLogger().Fatalf("file %s appeared while the wallet was being created and no overwrite was confirmed — nothing was written", walletFile)
		}
	}

	err = w.StoreJSON()
	if err != nil {
		logger.GetLogger().Println(err)
		return
	}

	fmt.Printf("\nWallet address: %s\n", w.MainAddress.GetHex())
}

// walletFilePath is the file StoreJSON writes for this wallet number. Kept next
// to the overwrite guard so the guard can never end up checking a different path
// than the one that is about to be written.
// restoreIdentity sets the identity a restored wallet signs as. The phrase
// derives a key per scheme and slot, and which of them an identity's address
// came from depends on the schemes when it was created - so look for the one
// the chain knows instead of assuming the primary key.
func restoreIdentity(w *wallet.Wallet, online, primaryPaused bool, defaultSig, defaultSig2 string) {
	cands := []identityCandidate{
		{w.Account1.Address, w.SigName + " primary key"},
		{w.Account2.Address, w.SigName2 + " spare key"},
	}
	for _, d := range []struct {
		name    string
		primary bool
	}{{defaultSig, true}, {defaultSig2, false}} {
		if a, err := deriveAddress(w, d.name, d.primary); err == nil {
			cands = append(cands, identityCandidate{a, d.name + " key (default scheme)"})
		}
	}
	cands = identityCandidates(cands)
	if online {
		if c, ok := chooseRestoredIdentity(cands, knownOnChain); ok {
			w.MainAddress = c.addr
			w.Account1.PublicKey.MainAddress = c.addr
			w.Account2.PublicKey.MainAddress = c.addr
			fmt.Println("Restored the on-chain identity whose address comes from the", c.label)
			return
		}
		fmt.Println("WARNING: no identity of this phrase is registered on chain; treating it as a new one.")
		w.SetMainAddressFromLiveScheme(primaryPaused)
		return
	}
	fmt.Println("WARNING: no node to look the identity up; using the address of the primary key. If this wallet " +
		"was created under other schemes, run the generator again with a reachable node.")
	w.SetMainAddressFromLiveScheme(false)
}

func walletFilePath(homePath string, walletNumber int) string {
	return filepath.Join(homePath, "wallet"+strconv.Itoa(walletNumber)+".json")
}

// overwriteConfirmationPhrase is what the operator must type, verbatim, to
// destroy an existing wallet file. It deliberately names the wallet number: a
// bare "y" (or a reflex "yes") is exactly what a panicking operator types
// without reading, and the number is the thing they are most likely to have got
// wrong in the first place.
func overwriteConfirmationPhrase(walletNumber int) string {
	return fmt.Sprintf("overwrite wallet %d", walletNumber)
}

// checkOverwriteConfirmation reports whether answer is the exact confirmation
// phrase for walletNumber. Surrounding whitespace and letter case are ignored;
// nothing else is.
func checkOverwriteConfirmation(answer string, walletNumber int) error {
	want := overwriteConfirmationPhrase(walletNumber)
	got := strings.Join(strings.Fields(strings.ToLower(answer)), " ")
	if got != want {
		return fmt.Errorf("overwrite of wallet %d was not confirmed (expected exactly %q, got %q)", walletNumber, want, answer)
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
		return false, fmt.Errorf("cannot check whether wallet %d is occupied (%s): %v", walletNumber, walletFile, err)
	}

	fmt.Printf("\n!!! WARNING: wallet number %d ALREADY EXISTS !!!\n", walletNumber)
	fmt.Printf("File: %s\n", walletFile)
	fmt.Println("Continuing will OVERWRITE this file. The keys stored in it will be")
	fmt.Println("destroyed irreversibly — if this wallet was created before recovery")
	fmt.Println("phrases existed, this file is the only copy of its keys and nothing")
	fmt.Println("will rebuild them afterwards. The funds on it will be lost.")
	fmt.Println("If you only meant to restore a wallet from a phrase, use a FREE number.")
	fmt.Printf("\nTo overwrite, type exactly: %s\nOtherwise press Enter to abort.\n> ", overwriteConfirmationPhrase(walletNumber))

	answer, err := in.ReadString('\n')
	if err != nil && answer == "" {
		return false, fmt.Errorf("overwrite of wallet %d was not confirmed (%s): %v", walletNumber, walletFile, err)
	}
	if err := checkOverwriteConfirmation(answer, walletNumber); err != nil {
		return false, err
	}
	fmt.Printf("Overwrite of wallet %d confirmed (%s).\n", walletNumber, walletFile)
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
		return fmt.Errorf("expected %d answers, got %d", len(positions), len(answers))
	}
	for i, p := range positions {
		if p < 1 || p > len(words) {
			return fmt.Errorf("position %d out of range", p)
		}
		got := strings.ToLower(strings.TrimSpace(answers[i]))
		if got != words[p-1] {
			return fmt.Errorf("word at position %d does not match", p)
		}
	}
	return nil
}

// readNewPassword asks for the wallet password and its confirmation, up to
// three times. The generator creates validator wallets, so it enforces the
// minimum every other wallet-creating flow enforces (S10-02); with a weak
// password a leaked wallet file falls to offline guessing despite Argon2id.
func readNewPassword(read func() ([]byte, error)) ([]byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Print("Enter password: ")
		pw, err := read()
		if err != nil {
			return nil, err
		}
		if err := wallet.ValidatePasswordStrength(string(pw)); err != nil {
			fmt.Println(err)
			wallet.ZeroBytes(pw)
			continue
		}
		fmt.Print("Repeat password: ")
		again, err := read()
		if err != nil {
			wallet.ZeroBytes(pw)
			return nil, err
		}
		same := string(again) == string(pw)
		wallet.ZeroBytes(again)
		if !same {
			fmt.Println("passwords do not match")
			wallet.ZeroBytes(pw)
			continue
		}
		return pw, nil
	}
	return nil, fmt.Errorf("no acceptable password after 3 attempts (minimum %d characters, typed twice)", wallet.MinPasswordLength)
}

// chainSchemes asks the node at ip which signature schemes are in force and
// installs them as this process's config. The generator used to derive keys
// for the built-in defaults whatever the chain ran: after the chain replaced a
// scheme, a new wallet's address came from a key the chain no longer verifies,
// and the account could never be opened.
func chainSchemes(ip string) (sigName, sigName2 string, primaryPaused bool, err error) {
	address := net.JoinHostPort(ip, strconv.Itoa(tcpip.Ports[tcpip.RPCTopic]))
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return "", "", false, fmt.Errorf("no node RPC at %s: %w", address, err)
	}
	conn.Close()
	go clientrpc.ConnectRPC(ip)
	reply := clientrpc.Call(common.BytesToLenAndBytes([]byte("ENCR")))
	if bytes.Equal(reply, []byte("Timeout")) {
		return "", "", false, fmt.Errorf("node at %s did not answer", address)
	}
	enc1b, left, err := common.BytesWithLenToBytes(reply)
	if err != nil {
		return "", "", false, err
	}
	enc2b, _, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return "", "", false, err
	}
	enc1, err := blocks.FromBytesToEncryptionConfig(enc1b, true)
	if err != nil {
		return "", "", false, err
	}
	enc2, err := blocks.FromBytesToEncryptionConfig(enc2b, false)
	if err != nil {
		return "", "", false, err
	}
	common.SetEncryption(enc1.SigName, enc1.PubKeyLength, enc1.PrivateKeyLength, enc1.SignatureLength, enc1.IsPaused, true)
	common.SetEncryption(enc2.SigName, enc2.PubKeyLength, enc2.PrivateKeyLength, enc2.SignatureLength, enc2.IsPaused, false)
	return enc1.SigName, enc2.SigName, enc1.IsPaused, nil
}

// knownOnChain reports whether any key is registered under identity a.
func knownOnChain(a common.Address) bool {
	keys, err := wallet.ParsePUBA(clientrpc.Call(common.BytesToLenAndBytes(append([]byte("PUBA"), a.GetBytes()...))))
	return err == nil && (keys.AnyPrimary || keys.AnySecondary)
}

// identityCandidate is an address the phrase may own, with where it comes from.
type identityCandidate struct {
	addr  common.Address
	label string
}

func identityCandidates(in []identityCandidate) []identityCandidate {
	out := []identityCandidate{}
	for _, c := range in {
		dup := false
		for _, o := range out {
			if bytes.Equal(o.addr.GetBytes(), c.addr.GetBytes()) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, c)
		}
	}
	return out
}

// chooseRestoredIdentity picks the candidate the chain already knows. Which key
// an identity's address came from depends on the schemes when it was created
// (the defaults, a later primary, or the live spare during a pause), so a
// restore must find it rather than assume the first derived key.
func chooseRestoredIdentity(cands []identityCandidate, known func(common.Address) bool) (identityCandidate, bool) {
	for _, c := range cands {
		if known(c.addr) {
			return c, true
		}
	}
	return identityCandidate{}, false
}

// deriveAddress is the address of the key the phrase yields for one scheme
// and slot - a candidate identity.
func deriveAddress(w *wallet.Wallet, sigName string, primary bool) (common.Address, error) {
	acc, err := wallet.GenerateNewAccountFromSeed(*w, sigName, primary)
	if err != nil {
		return common.Address{}, err
	}
	return acc.Address, nil
}

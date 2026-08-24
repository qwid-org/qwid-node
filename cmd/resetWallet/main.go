// resetWallet is an operator tool for wallet files that no longer match the
// chain's signature schemes.
//
// It exists because a node's wallet file outlives the chain database. On a
// testnet the database is routinely deleted, which resets the chain to the
// genesis schemes — but the wallet file keeps whatever scheme it last adopted,
// and the node then signs with an algorithm the fresh chain does not expect
// ("incorrect signature size", or a header that never verifies). On a real
// network this cannot arise: the chain is not deleted underneath the wallet.
//
// The repair therefore lives here rather than in the node's load path, where it
// would be automatic magic guarding against a situation that only a wiped
// database can produce.
//
// The node MUST be stopped: it holds the wallet file and, for "inspect", the
// file is read directly.
//
// Usage:
//
//	resetWallet
//	    With no arguments: reset wallet 0 to its original state — the signature
//	    schemes this build starts a fresh chain with, and the keys the recovery
//	    phrase derives for them. This is the command to run before syncing a
//	    chain from scratch, once the database has been deleted.
//
//	resetWallet inspect <walletNumber>
//	    Print what the file claims and what it actually holds — scheme names,
//	    key lengths, addresses, archived per-scheme keys, whether a recovery
//	    phrase is present. No password needed; no secrets printed.
//
//	resetWallet realign <walletNumber> <sigName> <sigName2>
//	    Re-derive both accounts for the named schemes FROM THE RECOVERY PHRASE
//	    and keep MainAddress, so the wallet keeps its on-chain identity and its
//	    stake. Requires a phrase; refuses without one, because generating random
//	    keys would silently replace the staked identity.
//
//	resetWallet recreate <walletNumber> <sigName> <sigName2>
//	    Throw the keys away and generate NEW random ones for the named schemes.
//	    This is a NEW identity with no stake and no registered keys: only for a
//	    throwaway testnet wallet. Requires typing the wallet number back.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/wallet"
	"golang.org/x/term"
)

func main() {
	logger.InitLogger()
	defer logger.CloseLogger()

	args := os.Args[1:]

	// No arguments: the routine case. Reset wallet 0 to the schemes a fresh
	// chain starts with — common.SigName()/SigName2() are still the build's
	// defaults here, because nothing has loaded a chain config into them.
	if len(args) == 0 {
		fmt.Printf("resetting wallet 0 to this build's starting schemes: %s / %s\n",
			common.SigName(), common.SigName2())
		if err := rewrite("reset", 0, common.SigName(), common.SigName2()); err != nil {
			fmt.Println("reset failed:", err)
			os.Exit(1)
		}
		return
	}

	if len(args) < 2 {
		usage()
		os.Exit(2)
	}

	num, err := strconv.Atoi(args[1])
	if err != nil || num < 0 || num > 255 {
		fmt.Println("wallet number must be 0-255")
		os.Exit(2)
	}

	switch args[0] {
	case "inspect":
		if err := inspect(uint8(num)); err != nil {
			fmt.Println("inspect failed:", err)
			os.Exit(1)
		}
	case "realign", "recreate":
		if len(args) != 4 {
			usage()
			os.Exit(2)
		}
		if err := rewrite(args[0], uint8(num), args[2], args[3]); err != nil {
			fmt.Println(args[0], "failed:", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("usage:")
	fmt.Println("  resetWallet                                                 (reset wallet 0 to this build's starting schemes)")
	fmt.Println("  resetWallet inspect  <walletNumber>")
	fmt.Println("  resetWallet realign  <walletNumber> <sigName> <sigName2>   (re-derives from the recovery phrase, keeps the identity)")
	fmt.Println("  resetWallet recreate <walletNumber> <sigName> <sigName2>   (NEW random keys, NEW identity, no stake)")
	fmt.Println("run only while the node is stopped")
}

func walletPath(walletNumber uint8) (string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	// Same derivation the node uses (wallet.EmptyWallet): each wallet lives in
	// its own numbered directory, e.g. ~/.qwid/wallet/0/wallet0.json.
	dir := home + common.DefaultWalletHomePath + strconv.Itoa(int(walletNumber))
	return dir, filepath.Join(dir, "wallet"+strconv.Itoa(int(walletNumber))+".json"), nil
}

// inspect reads the file directly. It deliberately prints lengths and addresses
// only — never key material — so its output can be pasted into a bug report.
func inspect(walletNumber uint8) error {
	_, path, err := walletPath(walletNumber)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f struct {
		SigName           string `json:"sig_name"`
		SigName2          string `json:"sig_name_2"`
		EncryptedMnemonic []byte `json:"encrypted_mnemonic"`
		MainAddress       json.RawMessage `json:"main_address"`
		Account1 storedAccount            `json:"account_1"`
		Account2 storedAccount            `json:"account_2"`
		Accounts map[string]storedAccount `json:"accounts"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return err
	}

	fmt.Println("file:", path)
	fmt.Printf("recovery phrase present: %v\n", len(f.EncryptedMnemonic) > 0)
	fmt.Printf("main address (identity):  %s\n", showAddr(f.MainAddress))
	fmt.Println()
	report("primary  ", f.SigName, f.Account1)
	report("secondary", f.SigName2, f.Account2)

	if len(f.Accounts) > 0 {
		fmt.Println("\narchived per-scheme keys:")
		for name, a := range f.Accounts {
			fmt.Printf("  %-14s pubkey %4d bytes  address %s\n", name, len(a.PublicKey.ByteValue), showAddr(a.Address))
		}
	}
	return nil
}

type storedAccount struct {
	PublicKey struct {
		ByteValue []byte `json:"byte_value"`
	} `json:"public_key"`
	// Addresses are read as raw JSON: common.Address is serialised as a hex
	// string in some wallet files and as a byte_value object in others, and
	// inspect must survive both rather than refusing to report at all.
	Address            json.RawMessage `json:"address"`
	EncryptedSecretKey []byte          `json:"encrypted_secret_key"`
}

// showAddr renders whichever shape the file used, without interpreting it.
func showAddr(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "(absent)"
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString
	}
	var asObject struct {
		ByteValue []byte `json:"byte_value"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil && len(asObject.ByteValue) > 0 {
		return fmt.Sprintf("%x", asObject.ByteValue)
	}
	return strings.TrimSpace(string(raw))
}

// report is the whole point of inspect: put the claimed scheme next to the key
// actually stored, so a contradiction is visible rather than inferred.
func report(slot, claimed string, a storedAccount) {
	got := len(a.PublicKey.ByteValue)
	fmt.Printf("%s slot: names %q\n", slot, claimed)
	fmt.Printf("            stored pubkey: %d bytes, address %s, encrypted secret key %d bytes\n",
		got, showAddr(a.Address), len(a.EncryptedSecretKey))
	want, err := oqs.PubKeyLength(claimed)
	switch {
	case err != nil:
		fmt.Printf("            NOTE: %q is not a scheme this build knows\n", claimed)
	case got == 0:
		fmt.Printf("            NOTE: no public key stored in this slot\n")
	case got != want:
		fmt.Printf("            MISMATCH: %q expects %d bytes but %d are stored — this wallet signs with one algorithm while calling it another\n",
			claimed, want, got)
	default:
		fmt.Printf("            consistent\n")
	}
}

// originalAccount reproduces the wallet's key for one scheme without inventing
// anything: from the recovery phrase if there is one, otherwise from the
// per-scheme archive. Both sources hold the ORIGINAL key; a random key would
// not, and would silently replace the wallet's identity.
func originalAccount(w *wallet.Wallet, sigName string, primary bool) (wallet.Account, error) {
	if w.HasSeed() {
		acc, err := wallet.GenerateNewAccountFromSeed(*w, sigName, primary)
		if err != nil {
			return wallet.Account{}, fmt.Errorf("deriving the %s key from the recovery phrase: %v", sigName, err)
		}
		return acc, nil
	}
	if a, ok := w.Accounts[sigName]; ok {
		return a, nil
	}
	return wallet.Account{}, fmt.Errorf("this wallet has no recovery phrase and no archived %q key, so its original key cannot be reproduced. "+
		"Restore it from its 24-word phrase or a wallet-file backup, or use \"recreate\" if this is a throwaway "+
		"testnet wallet whose identity and stake you are willing to lose", sigName)
}

func rewrite(mode string, walletNumber uint8, sigName, sigName2 string) error {
	for _, n := range []string{sigName, sigName2} {
		if _, err := oqs.PubKeyLength(n); err != nil {
			return fmt.Errorf("%q is not a signature scheme this build knows: %v", n, err)
		}
	}
	dir, path, err := walletPath(walletNumber)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no wallet file at %s: %v", path, err)
	}

	fmt.Print("Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	fmt.Println()

	// Load naming the CURRENT stored schemes, so loading itself does not try to
	// adopt anything; the rewrite below is what changes the schemes.
	w, err := wallet.LoadJSONFromDir(dir, walletNumber, string(pw), sigName, sigName2)
	if err != nil {
		// A mismatched wallet may refuse to load under the target schemes. Say
		// so plainly rather than leaving the operator with a Go error.
		return fmt.Errorf("could not load the wallet under %q/%q: %v\n"+
			"run \"resetWallet inspect %d\" to see what the file actually holds",
			sigName, sigName2, err, walletNumber)
	}

	switch mode {
	case "reset":
		// Prefer the recovery phrase: derivation is self-verifying, so it
		// reproduces the ORIGINAL keys exactly. Fall back to the per-scheme
		// archive, which is the only other place an original key can survive.
		// Never generate anything random here — that would quietly hand the
		// wallet a new, unstaked identity under the name "reset".
		acc1, err1 := originalAccount(w, sigName, true)
		if err1 != nil {
			return err1
		}
		acc2, err2 := originalAccount(w, sigName2, false)
		if err2 != nil {
			return err2
		}
		w.Account1, w.Account2 = acc1, acc2
		// Restore the identity too. MainAddress is the address of the primary
		// key, and a scheme change used to drag it along to the new key's
		// address — leaving a file whose identity names one algorithm's key
		// while the primary slot holds another's. Resetting to the original
		// state means putting it back on the primary key.
		if before := w.MainAddress.GetHex(); before != acc1.Address.GetHex() {
			fmt.Printf("main address was %s, restoring to the primary key's address %s\n", before, acc1.Address.GetHex())
		}
		w.MainAddress = acc1.Address
		fmt.Println("restored both keys to their original values")
	case "realign":
		if !w.HasSeed() {
			return fmt.Errorf("this wallet has no recovery phrase, so its keys cannot be re-derived. " +
				"Restore it from its 24-word phrase or from a wallet-file backup, or use \"recreate\" " +
				"if this is a throwaway testnet wallet whose identity and stake you are willing to lose")
		}
		acc1, err := wallet.GenerateNewAccountFromSeed(*w, sigName, true)
		if err != nil {
			return fmt.Errorf("deriving the %s key: %v", sigName, err)
		}
		acc2, err := wallet.GenerateNewAccountFromSeed(*w, sigName2, false)
		if err != nil {
			return fmt.Errorf("deriving the %s key: %v", sigName2, err)
		}
		w.Account1, w.Account2 = acc1, acc2
		fmt.Println("re-derived both keys from the recovery phrase; identity kept")
	case "recreate":
		want := fmt.Sprintf("recreate wallet %d", walletNumber)
		fmt.Printf("\nThis DISCARDS the keys in wallet %d and generates new ones.\n", walletNumber)
		fmt.Println("The result is a NEW identity: no stake, no registered public keys, no funds.")
		fmt.Printf("To continue, type exactly: %s\n> ", want)
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.Join(strings.Fields(strings.ToLower(answer)), " ") != want {
			return fmt.Errorf("not confirmed; nothing was written")
		}
		acc1, err := wallet.GenerateNewAccount(*w, sigName)
		if err != nil {
			return fmt.Errorf("generating the %s key: %v", sigName, err)
		}
		acc2, err := wallet.GenerateNewAccount(*w, sigName2)
		if err != nil {
			return fmt.Errorf("generating the %s key: %v", sigName2, err)
		}
		w.Account1, w.Account2 = acc1, acc2
		w.MainAddress = acc1.Address
		fmt.Println("generated new keys; this wallet now has a NEW identity")
	}

	w.SigName, w.SigName2 = sigName, sigName2
	w.Account1.PublicKey.MainAddress = w.MainAddress
	w.Account2.PublicKey.MainAddress = w.MainAddress

	if err := w.StoreJSON(); err != nil {
		return fmt.Errorf("writing the wallet: %v", err)
	}
	fmt.Printf("wrote %s\n", path)
	fmt.Printf("  primary   %s  address %s\n", w.SigName, w.Account1.Address.GetHex())
	fmt.Printf("  secondary %s  address %s\n", w.SigName2, w.Account2.Address.GetHex())
	fmt.Printf("  main address (identity) %s\n", w.MainAddress.GetHex())
	return nil
}

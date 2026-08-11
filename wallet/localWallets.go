package wallet

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// Public keys of the wallets this node owns.
//
// The RPC signature check knew only the active (mining) wallet, so a webui
// unlocked with any other locally-generated wallet failed every signed
// operation: it could send transactions, since TRAN needs no signature, but
// could not read its own balance or history back.
//
// The operator's other wallets are equally theirs, so the node reads their
// public halves and accepts a signature from any of them. Only the public
// halves are read — they sit unencrypted in the wallet file beside the
// encrypted secret key — so no password is involved anywhere here, and none
// should be: the node has no business holding one.

// WalletPublicKeys is one local wallet's public identity.
//
// MainAddress says WHICH wallet a key belongs to, which the accountless path
// does not need but an address-carrying request does: it is how the node tells
// that a claimed account really is one of the operator's own wallets. It is
// left empty when the wallet file has no usable address, so a wallet with a
// malformed one still authenticates requests that name no account.
type WalletPublicKeys struct {
	Number      uint8
	MainAddress common.Address
	Primary     []byte
	Secondary   []byte
}

// walletFileDoc mirrors just the fields needed from a wallet file. Decoding
// into this instead of Wallet avoids dragging in the encrypted material and
// keeps the reader tolerant of format additions.
type walletFileDoc struct {
	WalletNumber uint8 `json:"wallet_number"`
	// Decoded as a string rather than a common.Address: the address type's
	// UnmarshalJSON is strict about length and prefix, and a wallet file it
	// rejects must still yield its public keys.
	MainAddress string `json:"main_address"`
	Account1    struct {
		PublicKey struct {
			ByteValue []byte `json:"byte_value"`
		} `json:"public_key"`
	} `json:"account_1"`
	Account2 struct {
		PublicKey struct {
			ByteValue []byte `json:"byte_value"`
		} `json:"public_key"`
	} `json:"account_2"`
}

// parseWalletAddress decodes the hex address a wallet file stores, returning
// the empty address for anything it cannot read. An unusable address only costs
// that wallet the right to be matched by name; its keys still authenticate
// requests that name no account.
func parseWalletAddress(s string) common.Address {
	addr := common.EmptyAddress()
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(raw) != common.AddressLength {
		return addr
	}
	if err := addr.Init(raw); err != nil {
		return common.EmptyAddress()
	}
	return addr
}

// LocalWalletPublicKeysFromDir scans walletDir for wallet files, laid out as
// <dir>/<number>/wallet<number>.json, and returns each wallet's public keys.
//
// An entry that cannot be read or parsed is skipped with a log line rather than
// failing the scan: one corrupt wallet directory must not stop a node from
// starting, nor make the operator's other wallets unusable.
func LocalWalletPublicKeysFromDir(walletDir string) ([]WalletPublicKeys, error) {
	entries, err := os.ReadDir(walletDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	keys := make([]WalletPublicKeys, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		number, convErr := strconv.Atoi(e.Name())
		if convErr != nil || number < 0 || number > 255 {
			continue
		}
		path := filepath.Join(walletDir, e.Name(), "wallet"+e.Name()+".json")
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		var doc walletFileDoc
		if jsonErr := json.Unmarshal(raw, &doc); jsonErr != nil {
			logger.GetLogger().Println("skipping unreadable wallet file", path, ":", jsonErr)
			continue
		}
		primary := doc.Account1.PublicKey.ByteValue
		secondary := doc.Account2.PublicKey.ByteValue
		if len(primary) == 0 && len(secondary) == 0 {
			continue
		}
		keys = append(keys, WalletPublicKeys{
			Number:      uint8(number),
			MainAddress: parseWalletAddress(doc.MainAddress),
			Primary:     primary,
			Secondary:   secondary,
		})
	}
	return keys, nil
}

// LocalWalletPublicKeys scans the node's wallet directory, the parent of the
// per-wallet directories EmptyWallet builds its HomePath from.
func LocalWalletPublicKeys() ([]WalletPublicKeys, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	// DefaultWalletHomePath ends in the separator before the wallet number, so
	// trimming it yields the directory holding every numbered wallet.
	return LocalWalletPublicKeysFromDir(
		filepath.Clean(home + common.DefaultWalletHomePath))
}

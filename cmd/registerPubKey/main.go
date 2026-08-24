// registerPubKey is an operator recovery tool: it registers a validator's
// public key directly in the LOCAL node database, exactly as if a block-carried
// announcement had been processed (blocks.StorePubKey + patricia trie).
//
// Use case: a node cannot verify another validator's blocks because that
// validator's key for a newly voted-in signature scheme never propagated (the
// pre-fix self-registration bug). Injecting the peer's public key unblocks
// verification of the already-produced blocks.
//
// The key is self-certifying: its address is derived from the key bytes, so a
// wrong or tampered key simply registers a useless address and cannot hijack an
// existing one. The main address, however, decides whose identity the key is
// attached to - copy it exactly from the owning node.
//
// Usage (the node MUST be stopped - RocksDB allows one writer; operates on
// $HOME/.qwid/db/blockchain of the CURRENT user):
//
//	go run cmd/registerPubKey/main.go <mainAddressHex> <pubKeyHex> <primary|secondary>
//	go run cmd/registerPubKey/main.go list <mainAddressHex>
//
// The owning node prints both values at startup (cmd/mining logs "MainAddress"
// and the "pub_key" / "pub_key_2" hex). "list" shows every key currently
// registered under a main address, with lengths - use it to confirm the
// injection landed in the database the node actually reads.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/pubkeys"
)

func main() {
	logger.InitLogger()
	defer logger.CloseLogger()

	if len(os.Args) == 3 && os.Args[1] == "list" {
		listKeys(os.Args[2])
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "header" {
		describeHeader(os.Args[2])
		return
	}
	if len(os.Args) != 4 || (os.Args[3] != "primary" && os.Args[3] != "secondary") {
		fmt.Println("usage: registerPubKey <mainAddressHex> <pubKeyHex> <primary|secondary>")
		fmt.Println("       registerPubKey list <mainAddressHex>")
		fmt.Println("run only while the node is stopped")
		os.Exit(2)
	}
	mainAddrHex, pubKeyHex, slot := os.Args[1], os.Args[2], os.Args[3]
	primary := slot == "primary"

	mainAddrBytes, err := hex.DecodeString(mainAddrHex)
	if err != nil {
		fmt.Println("bad main address hex:", err)
		os.Exit(1)
	}
	mainAddress, err := common.BytesToAddress(mainAddrBytes)
	if err != nil {
		fmt.Println("bad main address:", err)
		os.Exit(1)
	}
	keyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		fmt.Println("bad pubkey hex:", err)
		os.Exit(1)
	}
	address, err := common.PubKeyToAddress(keyBytes, primary)
	if err != nil {
		fmt.Println("cannot derive address from pubkey:", err)
		os.Exit(1)
	}
	// Built directly (not via PubKey.Init) so a key of a scheme the local
	// default config does not know yet (e.g. Falcon-1024) is accepted.
	pk := common.PubKey{
		ByteValue:   keyBytes,
		Address:     address,
		MainAddress: mainAddress,
		Primary:     primary,
	}

	database.InitDB()
	defer database.CloseDB()
	pubkeys.InitTrie()

	if err := blocks.StorePubKey(pk); err != nil {
		fmt.Println("StorePubKey failed:", err)
		os.Exit(1)
	}
	if err := blocks.StorePubKeyInPatriciaTrie(pk); err != nil {
		fmt.Println("StorePubKeyInPatriciaTrie failed:", err)
		os.Exit(1)
	}
	// Read back through the exact lookup the node's verifier uses.
	got, err := pubkeys.LoadPubKeyWithPrimaryOfLength(mainAddress, primary, len(keyBytes))
	if err != nil || got.GetHex() != pubKeyHex {
		fmt.Println("VERIFICATION FAILED: key not found back under the main address:", err)
		os.Exit(1)
	}
	fmt.Printf("registered and verified %s key of %d bytes as address %s under main address %s\n",
		slot, len(keyBytes), address.GetHex(), mainAddress.GetHex())
}

// describeHeader prints, for a stored block, exactly what its header
// verification will look for: the operator (main) address, which signature
// slot the header used, the scheme names from the header's own encryption
// config, and every key currently registered under that operator. The printed
// operator address is the exact value to pass to the register command.
func describeHeader(heightStr string) {
	height, err := strconv.ParseInt(heightStr, 10, 64)
	if err != nil {
		fmt.Println("bad height:", err)
		os.Exit(1)
	}
	database.InitDB()
	defer database.CloseDB()
	pubkeys.InitTrie()

	block, err := blocks.LoadBlock(height)
	if err != nil {
		fmt.Println("cannot load block", height, ":", err)
		os.Exit(1)
	}
	bh := block.GetHeader()
	operator := bh.OperatorAccount
	sig := bh.Signature.GetBytes()
	slot := "unknown (empty signature)"
	if len(sig) > 0 {
		if sig[0] == 0 {
			slot = "primary"
		} else {
			slot = "secondary"
		}
	}
	fmt.Printf("block %d\n", height)
	fmt.Printf("  operator (main) address: %s\n", hex.EncodeToString(operator.GetBytes()))
	fmt.Printf("  header signed with:      %s key (signature %d bytes)\n", slot, len(sig))
	if sigName, sigName2, isPaused, isPaused2, err := block.GetSigNames(); err == nil {
		fmt.Printf("  header scheme config:    primary=%s (paused=%v)  secondary=%s (paused=%v)\n",
			sigName, isPaused, sigName2, isPaused2)
	} else {
		fmt.Println("  header scheme config:    unreadable:", err)
	}
	fmt.Println("  keys registered under this operator in THIS database:")
	addresses, err := pubkeys.LoadAddresses(operator)
	if err != nil {
		fmt.Println("    none - no address trie:", err)
		return
	}
	for i, a := range addresses {
		s := "secondary"
		if a.Primary {
			s = "primary"
		}
		pk, err := pubkeys.LoadPubKey(a.GetBytes())
		if err != nil {
			fmt.Printf("    %d: %s address %s - NO KEY STORED (%v)\n", i, s, a.GetHex(), err)
			continue
		}
		fmt.Printf("    %d: %s address %s - key length %d bytes\n", i, s, a.GetHex(), len(pk.GetBytes()))
	}
}

// listKeys prints every key registered under a main address, newest last.
func listKeys(mainAddrHex string) {
	mainAddrBytes, err := hex.DecodeString(mainAddrHex)
	if err != nil {
		fmt.Println("bad main address hex:", err)
		os.Exit(1)
	}
	mainAddress, err := common.BytesToAddress(mainAddrBytes)
	if err != nil {
		fmt.Println("bad main address:", err)
		os.Exit(1)
	}
	database.InitDB()
	defer database.CloseDB()
	pubkeys.InitTrie()

	addresses, err := pubkeys.LoadAddresses(mainAddress)
	if err != nil {
		fmt.Println("no address trie for this main address:", err)
		os.Exit(1)
	}
	for i, a := range addresses {
		slot := "secondary"
		if a.Primary {
			slot = "primary"
		}
		pk, err := pubkeys.LoadPubKey(a.GetBytes())
		if err != nil {
			fmt.Printf("%d: %s address %s - NO KEY STORED (%v)\n", i, slot, a.GetHex(), err)
			continue
		}
		fmt.Printf("%d: %s address %s - key length %d bytes\n", i, slot, a.GetHex(), len(pk.GetBytes()))
	}
}

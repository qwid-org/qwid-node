package blocks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/wallet"
)

func StoreAddress(mainAddress common.Address, pk common.PubKey) error {
	index, err := pubkeys.FindAddressForMainAddress(mainAddress, pk.Address)
	if err != nil {
		return err
	}
	if index >= 0 {
		return fmt.Errorf("address just stored before")
	}
	err = pubkeys.AddPubKeyToAddress(pk, mainAddress)
	if err != nil {
		return err
	}
	return nil
}

func AddNewPubKeyToActiveWallet(sigName string, primary bool, height int64) error {
	w := wallet.GetActiveWallet()
	if w.GetSigName(primary) != sigName {
		previousSigName := w.GetSigName(primary)
		if primary {
			w.SigName = sigName
		} else {
			w.SigName2 = sigName
		}
		err := w.AddNewEncryptionToActiveWallet(sigName, primary)
		if err != nil {
			// Put the scheme name back. AddNewEncryptionToActiveWallet refuses
			// for a wallet with no recovery phrase, and leaving SigName pointing
			// at a scheme this wallet holds no key for would make any later
			// StoreJSON archive the OLD key under the NEW scheme name — the very
			// stale-archive confusion the refusal is meant to avoid.
			if primary {
				w.SigName = previousSigName
			} else {
				w.SigName2 = previousSigName
			}
			logger.GetLogger().Printf("CANNOT ADOPT THE NEW SIGNATURE SCHEME %q: %v — "+
				"this node keeps following the chain, but it now has NO key for %q and cannot produce "+
				"blocks or sign transactions under it until the operator restores this wallet from its "+
				"recovery phrase or from a wallet-file backup", sigName, err, sigName)
			return err
		}
	}
	if !primary {
		logger.GetLogger().Println("NEW SECONDARY KEY DERIVED AND STORED IN THE WALLET. It is NOT registered anywhere yet: " +
			"the operator must register it MANUALLY by sending a transaction with the pubkey included, signed with the new " +
			"key. Until that transaction is in a block, this node signs nonces and block headers with the primary key")
	}
	// Deliberately NOT registering the new key in the local pubkey DB/trie here.
	// Registration is consensus state with exactly one channel: a transaction
	// carrying the pubkey, sent manually by the operator and processed by
	// ProcessBlockPubKey on every node when its block is applied. Self-
	// registering here made the local DB diverge from the rest of the network
	// (this node considered its key known while no other node had it).
	err := w.StoreJSON()
	if err != nil {
		return err
	}
	return nil
}

//func GetMainAddress(a common.Address) (common.Address, error) {
//	pk, err := memDatabase.LoadPubKey(a.GetBytes())
//	if err != nil {
//		return common.Address{}, err
//	}
//	return pk.MainAddress, nil
//}

func StorePubKey(pk common.PubKey) error {
	a, err := common.PubKeyToAddress(pk.GetBytes(), pk.Primary)
	if err != nil {
		return err
	}
	if !bytes.Equal(a.GetBytes(), pk.Address.GetBytes()) {
		return fmt.Errorf("address is different in pubkey and recovered from bytes")
	}
	//err = memDatabase.MainDB.Put(append(common.PubKeyDBPrefix[:], a.GetBytes()...), pk.GetBytes())
	//if err != nil {
	//	return err
	//}
	pkm, err := json.Marshal(pk)
	if err != nil {
		return err
	}
	err = database.MainDB.Put(append(common.PubKeyMarshalDBPrefix[:], a.GetBytes()...), pkm)
	return err
}

func StorePubKeyInPatriciaTrie(pk common.PubKey) error {
	addresses, err := pubkeys.LoadAddresses(pk.MainAddress)
	if err != nil {
		if err.Error() != "key not found" {
			logger.GetLogger().Println(err)
			return err
		}
		logger.GetLogger().Println("OK", err)
		addresses = []common.Address{}
	}
	if len(addresses) == 0 {
		mainAddress, err2 := pubkeys.CreateAddressFromFirstPubKey(pk)
		if err2 != nil {
			return err2
		}
		if !bytes.Equal(pk.MainAddress.GetBytes(), mainAddress.GetBytes()) {
			return fmt.Errorf("error with creation of address from first pub key %v != %v", pk.MainAddress.GetHex(), mainAddress.GetHex())
		}
		return nil
	}
	exist := false
	for _, a := range addresses {
		if bytes.Equal(a.GetBytes(), pk.Address.GetBytes()) {
			exist = true
			break
		}
	}
	if exist {
		//logger.GetLogger().Println(" address from pub key is just stored in mainaddress of patricia trie")
		return nil
	}

	address, err := common.PubKeyToAddress(pk.GetBytes(), pk.Primary)
	if err != nil {
		return err
	}
	addresses = append(addresses, address)
	tree, err := pubkeys.BuildMerkleTree(pk.MainAddress, addresses, pubkeys.GlobalMerkleTree.DB)
	if err != nil {
		return err
	}
	for _, a := range addresses {
		if !tree.IsAddressInTree(a) {
			return fmt.Errorf("pubkey patricia trie fails to add pubkey")
		}
	}
	err = tree.StoreTree(pk.MainAddress)
	if err != nil {
		return err
	}

	return nil
}

// LoadPubKey : a - address in bytes of pubkey
//func LoadPubKey(a []byte, mainAddress common.Address) (pk *common.PubKey, err error) {
//	pkb, err := memDatabase.MainDB.Get(append(common.PubKeyDBPrefix[:], a...))
//	if err != nil {
//		return &common.PubKey{}, err
//	}
//	err = pk.Init(pkb, mainAddress)
//	if err != nil {
//		return &common.PubKey{}, err
//	}
//	return pk, nil
//}

// ProcessBlockPubKey : store pubkey on each transaction
func ProcessBlockPubKey(block Block) error {
	for _, txh := range block.TransactionsHashes {
		t, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], txh.GetBytes())
		if err != nil {
			//TODO
			//transactionsDefinition.RemoveTransactionFromDBbyHash(common.TransactionPoolHashesDBPrefix[:], txh.GetBytes())
			return err
		}
		pk := t.TxData.Pubkey
		// Skip if pubkey bytes are empty (no pubkey included in transaction)
		if len(pk.GetBytes()) == 0 {
			continue
		}
		logger.GetLogger().Println("ProcessBlockPubKey: pubkey found in transaction", txh.GetHex())
		logger.GetLogger().Println("  PubKey bytes length:", len(pk.GetBytes()))
		logger.GetLogger().Println("  PubKey.Address:", pk.Address.GetHex())
		logger.GetLogger().Println("  PubKey.MainAddress:", pk.MainAddress.GetHex())
		logger.GetLogger().Println("  PubKey.Primary:", pk.Primary)
		senderAddr := t.GetSenderAddress()
		logger.GetLogger().Println("  Transaction sender:", senderAddr.GetHex())

		zeroBytes := make([]byte, common.AddressLength)
		// Derive address from pubkey bytes if not set
		if bytes.Equal(pk.Address.GetBytes(), zeroBytes) {
			logger.GetLogger().Println("  PubKey.Address is empty, deriving from pubkey bytes...")
			derivedAddr, err := common.PubKeyToAddress(pk.GetBytes(), pk.Primary)
			if err != nil {
				logger.GetLogger().Println("  ERROR: cannot derive address from pubkey:", err)
				continue
			}
			pk.Address = derivedAddr
			logger.GetLogger().Println("  Derived address:", pk.Address.GetHex())
		}
		// Set MainAddress if not set
		if bytes.Equal(pk.MainAddress.GetBytes(), zeroBytes) {
			logger.GetLogger().Println("  PubKey.MainAddress is empty, setting to pk.Address")
			pk.MainAddress = pk.Address
			logger.GetLogger().Println("  MainAddress set to:", pk.MainAddress.GetHex())
		}
		err = StorePubKey(pk)
		if err != nil {
			logger.GetLogger().Println("  ERROR: StorePubKey failed:", err)
			return err
		}
		logger.GetLogger().Println("  StorePubKey success")
		err = StorePubKeyInPatriciaTrie(pk)
		if err != nil {
			logger.GetLogger().Println("  ERROR: StorePubKeyInPatriciaTrie failed:", err)
			return err
		}
		logger.GetLogger().Println("  StorePubKeyInPatriciaTrie success")
	}
	return nil
}

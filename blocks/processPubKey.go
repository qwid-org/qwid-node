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
	// Invalidate AFTER the write, so the database already holds the new record
	// when the cached decode is dropped. A reader that fetched the old record
	// just before this Put is handled by the cache's generation counter, which
	// makes it discard what it read rather than cache a superseded key.
	pubkeys.InvalidatePubKeyCache(a.GetBytes())
	return err
}

func StorePubKeyInPatriciaTrie(pk common.PubKey) error {
	// QWID-2026-16 (defense in depth): reject a key whose byte length matches no
	// active scheme even if it reached application. Transaction.Verify already
	// gates this, but application must not depend on that alone — a key admitted
	// through any other path (a future caller, a verification bug) would
	// otherwise bloat the trie with unverifiable bytes.
	if !common.IsValidPubKeyLength(len(pk.GetBytes()), pk.Primary) {
		return fmt.Errorf("refusing to register pubkey of length %d matching no active scheme", len(pk.GetBytes()))
	}
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
		// This identity has no trie yet, so this key is its first. There are two
		// shapes of "first key" and only one of them may go through
		// CreateAddressFromFirstPubKey.
		//
		// That helper bootstraps an identity OUT OF the key: it derives an
		// address from the key bytes and makes that address the identity. It is
		// therefore correct only when the key actually derives MainAddress —
		// the classic case of a primary key registering itself.
		//
		// A key whose derived address differs from MainAddress (any secondary
		// key, and any key of a newly voted-in scheme) cannot bootstrap an
		// identity it does not derive. Transaction verification already permits
		// exactly this case: its bootstrap rule accepts a non-primary key when
		// pk.MainAddress equals the sender, without requiring the key to derive
		// it. Sending such a key down the helper's path made verification and
		// application disagree — the block was accepted into the chain and then
		// refused when applied, so the node rewound and retried it forever.
		//
		// Worse, the helper stores the derived-address trie BEFORE its caller
		// checks the identity matches, so the first failed attempt left that
		// trie behind and every retry then failed with a different error
		// ("there are just generated markle trie for given pubkey") — a block
		// the node could never get past.
		derived, derr := common.PubKeyToAddress(pk.GetBytes(), pk.Primary)
		if derr != nil {
			return derr
		}
		if bytes.Equal(derived.GetBytes(), pk.MainAddress.GetBytes()) {
			mainAddress, err2 := pubkeys.CreateAddressFromFirstPubKey(pk)
			if err2 != nil {
				return err2
			}
			if !bytes.Equal(pk.MainAddress.GetBytes(), mainAddress.GetBytes()) {
				return fmt.Errorf("error with creation of address from first pub key %v != %v", pk.MainAddress.GetHex(), mainAddress.GetHex())
			}
			return nil
		}
		// The identity is the one the key names, not one derived from it: open
		// its trie with this key's address as the sole entry. This is the same
		// construction the append path below performs, from an empty start.
		addresses = []common.Address{}
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
	// QWID-2026-16: cap the number of keys one identity may register. Without
	// this an attacker holding a single identity could sign an unbounded stream
	// of distinct registrations, each growing this list (rebuilt in full on
	// every registration) without limit.
	if len(addresses) >= common.MaxKeysPerIdentity {
		return fmt.Errorf("identity %s already registered the maximum %d public keys",
			pk.MainAddress.GetHex(), common.MaxKeysPerIdentity)
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
		// One line per registration, not the fifteen this used to emit. Every
		// fact those lines carried is either in the summary below or in the
		// error that reports the failure, and each error names the transaction
		// and the addresses itself so nothing depends on a preceding line
		// having survived. Registrations are rare on a live chain but arrive
		// back to back while syncing one, which is where the volume hurt.
		senderAddr := t.GetSenderAddress()

		zeroBytes := make([]byte, common.AddressLength)
		// Derive address from pubkey bytes if not set
		if bytes.Equal(pk.Address.GetBytes(), zeroBytes) {
			derivedAddr, err := common.PubKeyToAddress(pk.GetBytes(), pk.Primary)
			if err != nil {
				logger.GetLogger().Printf("ERROR: tx %s carries a pubkey whose address cannot be derived: %v", txh.GetHex(), err)
				continue
			}
			pk.Address = derivedAddr
		}
		// Set MainAddress if not set
		if bytes.Equal(pk.MainAddress.GetBytes(), zeroBytes) {
			pk.MainAddress = pk.Address
		}
		// Defence in depth. Verify() is the consensus gate and now requires the
		// enclosed key to name its sender as its identity, so this cannot fire
		// for a transaction that passed it. It is here because the binding
		// written below is what LoadPubKey later reports as "this key belongs
		// to X", and a signature made with the key then spends X's coins: any
		// future gap in Verify would become a permanent on-chain account
		// takeover the moment the block applied.
		//
		// Skipping rather than rejecting the block is deliberate. Refusing the
		// block would stall the node on a rewind-and-reapply loop — the failure
		// mode that stalled it once already — whereas skipping leaves the key
		// simply unbound, which is what an unproven claim deserves.
		if !bytes.Equal(pk.MainAddress.GetBytes(), senderAddr.GetBytes()) {
			logger.GetLogger().Printf("WARNING: refusing to register a key that names identity %s while sent by %s; key not bound",
				pk.MainAddress.GetHex(), senderAddr.GetHex())
			continue
		}

		// Is this a genuinely NEW registration for the identity? Only new ones
		// are journalled, so a rewind never undoes a key that a still-canonical
		// earlier block first registered (QWID-2026-07 annex). A duplicate
		// registration tx in a later block is a no-op in the trie and must not
		// produce a journal entry that would later delete the canonical key.
		isNew := true
		if idx, ferr := pubkeys.FindAddressForMainAddress(pk.MainAddress, pk.Address); ferr == nil && idx >= 0 {
			isNew = false
		}

		err = StorePubKey(pk)
		if err != nil {
			logger.GetLogger().Printf("ERROR: storing the key %s of identity %s from tx %s failed: %v",
				pk.Address.GetHex(), pk.MainAddress.GetHex(), txh.GetHex(), err)
			return err
		}
		err = StorePubKeyInPatriciaTrie(pk)
		if err != nil {
			logger.GetLogger().Printf("ERROR: recording the key %s under identity %s from tx %s failed: %v",
				pk.Address.GetHex(), pk.MainAddress.GetHex(), txh.GetHex(), err)
			return err
		}
		if isNew {
			journalPubKeyRegistration(block.GetHeader().Height, pk.Address, pk.MainAddress)
		}
		logger.GetLogger().Printf("registered %s key %s (%d bytes) for identity %s from tx %s",
			map[bool]string{true: "primary", false: "secondary"}[pk.Primary],
			pk.Address.GetHex(), len(pk.GetBytes()), pk.MainAddress.GetHex(), txh.GetHex())
	}
	return nil
}

// pubKeyJournalKey builds the registration-journal key for one derived address
// at a block height (QWID-2026-07 annex).
func pubKeyJournalKey(height int64, derived common.Address) []byte {
	k := append(common.PubKeyRegistrationJournalDBPrefix[:], common.GetByteInt64(height)...)
	return append(k, derived.GetBytes()...)
}

// journalPubKeyRegistration records that block `height` newly registered
// `derived` under identity `mainAddr`, so UnregisterPubKeysAtHeight can undo
// exactly this registration if the block is later rewound.
func journalPubKeyRegistration(height int64, derived, mainAddr common.Address) {
	if err := database.MainDB.Put(pubKeyJournalKey(height, derived), mainAddr.GetBytes()); err != nil {
		// Best effort: a journal write failure only weakens rewind cleanup; it
		// must not fail block application (the block is already valid).
		logger.GetLogger().Printf("WARNING: could not journal pubkey registration of %s at height %d: %v",
			derived.GetHex(), height, err)
	}
}

// UnregisterPubKeysAtHeight undoes every pubkey registration the journal records
// for the given block height, called from RemoveBlockFromDB during a rewind so an
// orphaned branch's registrations do not persist and shadow the canonical chain
// (QWID-2026-07 annex). Best-effort: errors are logged, never fatal to the rewind.
func UnregisterPubKeysAtHeight(height int64) {
	prefix := append(common.PubKeyRegistrationJournalDBPrefix[:], common.GetByteInt64(height)...)
	keys, err := database.MainDB.LoadAllKeys(prefix)
	if err != nil {
		logger.GetLogger().Println("pubkey journal scan failed at height", height, ":", err)
		return
	}
	const keyLen = 2 + 8 + common.AddressLength
	for _, k := range keys {
		if len(k) != keyLen {
			continue
		}
		var derived common.Address
		copy(derived.ByteValue[:], k[10:keyLen])
		mainB, gerr := database.MainDB.Get(k)
		if gerr != nil || len(mainB) < common.AddressLength {
			_ = database.MainDB.Delete(k)
			continue
		}
		var mainAddr common.Address
		copy(mainAddr.ByteValue[:], mainB[:common.AddressLength])
		unregisterPubKey(derived, mainAddr)
		_ = database.MainDB.Delete(k)
	}
}

// unregisterPubKey removes one key record and drops its derived address from the
// identity's patricia trie (rebuilding the trie, or removing it entirely when the
// identity has no keys left). Mirror of StorePubKey + StorePubKeyInPatriciaTrie.
func unregisterPubKey(derived, mainAddr common.Address) {
	_ = database.MainDB.Delete(append(common.PubKeyMarshalDBPrefix[:], derived.GetBytes()...))
	pubkeys.InvalidatePubKeyCache(derived.GetBytes())

	addrs, err := pubkeys.LoadAddresses(mainAddr)
	if err != nil {
		return
	}
	kept := make([]common.Address, 0, len(addrs))
	for _, a := range addrs {
		if !bytes.Equal(a.GetBytes(), derived.GetBytes()) {
			kept = append(kept, a)
		}
	}
	if len(kept) == len(addrs) {
		return // nothing removed
	}
	if len(kept) == 0 {
		if rerr := pubkeys.RemoveMerkleTrieFromDB(mainAddr); rerr != nil {
			logger.GetLogger().Println("cannot remove pubkey trie for", mainAddr.GetHex(), ":", rerr)
		}
		return
	}
	tree, terr := pubkeys.BuildMerkleTree(mainAddr, kept, pubkeys.GlobalMerkleTree.DB)
	if terr != nil {
		logger.GetLogger().Println("cannot rebuild pubkey trie for", mainAddr.GetHex(), ":", terr)
		return
	}
	if serr := tree.StoreTree(mainAddr); serr != nil {
		logger.GetLogger().Println("cannot store rebuilt pubkey trie for", mainAddr.GetHex(), ":", serr)
	}
}

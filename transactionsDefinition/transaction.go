package transactionsDefinition

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/wallet"
)

var cancelTransactionPrefix = []byte("QWID_CANCEL_V1")

// CancellationOptData returns the consensus payload for cancelling a delayed
// escrow transaction. The payload is covered by the transaction hash/signature.
func CancellationOptData(target common.Hash) []byte {
	payload := make([]byte, 0, len(cancelTransactionPrefix)+common.HashLength)
	payload = append(payload, cancelTransactionPrefix...)
	payload = append(payload, target.GetBytes()...)
	return payload
}

// CancellationTarget identifies a protocol cancellation transaction.
func (tx Transaction) CancellationTarget() (common.Hash, bool) {
	data := tx.TxData.OptData
	if len(data) != len(cancelTransactionPrefix)+common.HashLength ||
		!bytes.Equal(data[:len(cancelTransactionPrefix)], cancelTransactionPrefix) {
		return common.Hash{}, false
	}
	return common.GetHashFromBytes(data[len(cancelTransactionPrefix):]), true
}

type Transaction struct {
	TxData          TxData           `json:"tx_data"`
	TxParam         TxParam          `json:"tx_param"`
	Hash            common.Hash      `json:"hash"`
	Signature       common.Signature `json:"signature"`
	Height          int64            `json:"height"`
	GasPrice        int64            `json:"gas_price"`
	GasUsage        int64            `json:"gas_usage"`
	OutputLogs      []byte           `json:"outputLogs,omitempty"`
	ContractAddress common.Address   `json:"contractAddress,omitempty"`
}

func (mt *Transaction) GetData() TxData {
	return mt.TxData
}

func (mt *Transaction) GetParam() TxParam {
	return mt.TxParam
}

func (mt *Transaction) GasUsageEstimate() int64 {
	gas := len(mt.TxData.OptData) * 100
	gas += len(mt.TxData.Pubkey.GetBytes()) * 100
	return int64(gas) + 30000
}

func (mt *Transaction) GetGasUsage() int64 {
	return 2100
}

// CalcFee returns GasPrice*GasUsage with overflow and sign checking (AC-C2).
// The prior `GasPrice * GasUsage` could overflow int64 and wrap to a negative
// value, bypassing fee checks. Callers must treat a non-nil error as an invalid
// transaction.
func (mt *Transaction) CalcFee() (int64, error) {
	if mt.GasPrice < 0 || mt.GasUsage < 0 {
		return 0, fmt.Errorf("negative gas price (%d) or usage (%d)", mt.GasPrice, mt.GasUsage)
	}
	fee := mt.GasPrice * mt.GasUsage
	// Detect overflow: if either operand is non-zero, dividing back must recover it.
	if mt.GasPrice != 0 && fee/mt.GasPrice != mt.GasUsage {
		return 0, fmt.Errorf("fee overflow: GasPrice=%d GasUsage=%d", mt.GasPrice, mt.GasUsage)
	}
	return fee, nil
}

func (mt *Transaction) GetSignature() common.Signature {
	return mt.Signature
}

func (mt *Transaction) GetHeight() int64 {
	return mt.Height
}

func (mt *Transaction) GetHash() common.Hash {
	return mt.Hash
}

func (tx *Transaction) GetString() string {
	t := "Common parameters:\n" + tx.TxParam.GetString() + "\n"
	t += "Data:\n" + tx.TxData.GetString() + "\n"
	t += "Block Height: " + strconv.FormatInt(tx.Height, 10) + "\n"
	t += "Gas Price: " + strconv.FormatInt(tx.GasPrice, 10) + "\n"
	t += "Gas Usage: " + strconv.FormatInt(tx.GasUsage, 10) + "\n"
	t += "Hash: " + tx.Hash.GetHex() + "\n"
	t += "Signature: " + tx.Signature.GetHex() + "\n"
	t += "Contract Address: " + tx.ContractAddress.GetHex() + "\n"
	t += "Contract Logs:\n" + string(tx.OutputLogs) + "\n"
	return t
}

func (tx *Transaction) GetSenderAddress() common.Address {
	return tx.TxParam.Sender
}

// txFixedFieldsBytes is what Transaction.GetFromBytes reads by fixed offset once
// TxParam and TxData are consumed: height, gas price, gas usage (8 each) and the
// transaction hash (32).
const txFixedFieldsBytes = 24 + common.HashLength

// minTransactionBytes is the structural lower bound on a serialised transaction,
// independent of ANY signature scheme: TxParam (43) + TxData (33) + the fixed
// fields above (56) + the signature length header (4) + the contract address
// (20) + the output-log length header (4).
//
// The bound deliberately excludes the signature body. It used to be derived from
// common.SignatureLength(true)/SignatureLength2(true) — the schemes THIS node
// currently runs — which made decoding depend on local state that a syncing node
// has wrong by definition: a node behind the chain still holds the schemes from
// its own height, so every transaction signed under a newer (and possibly much
// shorter) scheme was rejected here before it was ever parsed. That is fatal
// during sync, because this same decoder handles the "bx" answers carrying the
// very transactions the node is missing, and because a rejected transaction
// never enters the pool the peer re-gossips it forever.
//
// Whether the signature is well-formed is the signature check's business
// (Transaction.Verify), which resolves the scheme from the block being verified
// rather than from local configuration.
const minTransactionBytes = 43 + 33 + txFixedFieldsBytes + 4 + common.AddressLength + 4

func (tx *Transaction) GetFromBytes(b []byte) (Transaction, []byte, error) {

	if len(b) < minTransactionBytes {
		return Transaction{}, nil, fmt.Errorf("Not enough bytes for transaction unmarshal len bytes %v < %v", len(b), minTransactionBytes)
	}
	tp := TxParam{}
	tp, b, err := tp.GetFromBytes(b)
	if err != nil {
		return Transaction{}, nil, err
	}
	td := TxData{}
	adata, b, err := td.GetFromBytes(b)
	if err != nil {
		return Transaction{}, nil, err
	}
	// TxParam/TxData are variable-length, so the top-level bound above says
	// nothing about what is left for the fixed fields read by offset below.
	if len(b) < txFixedFieldsBytes {
		return Transaction{}, nil, fmt.Errorf("not enough bytes for transaction fixed fields %v < %v", len(b), txFixedFieldsBytes)
	}
	at := Transaction{
		TxData:    adata,
		TxParam:   tp,
		Hash:      common.Hash{},
		Signature: common.Signature{},
		Height:    common.GetInt64FromByte(b[:8]),
		GasPrice:  common.GetInt64FromByte(b[8:16]),
		GasUsage:  common.GetInt64FromByte(b[16:24]),
	}
	at.Hash = common.GetHashFromBytes(b[24:txFixedFieldsBytes])
	vb, leftb, err := common.BytesWithLenToBytes(b[txFixedFieldsBytes:])
	if err != nil {
		return Transaction{}, nil, err
	}
	signature, err := common.GetSignatureFromBytes(vb, tp.Sender)
	if err != nil {
		return Transaction{}, nil, err
	}
	at.Signature = signature
	if len(leftb) < common.AddressLength {
		return Transaction{}, nil, fmt.Errorf("not enough bytes for contract address %v < %v", len(leftb), common.AddressLength)
	}
	err = at.ContractAddress.Init(leftb[:common.AddressLength])
	if err != nil {
		return Transaction{}, nil, err
	}
	toBytes, leftb2, err := common.BytesWithLenToBytes(leftb[common.AddressLength:])
	if err != nil {
		return Transaction{}, nil, err
	}
	at.OutputLogs = toBytes[:]
	return at, leftb2, nil
}

func (mt *Transaction) GetGasPrice() int64 {
	return mt.GasPrice
}

func (tx *Transaction) GetBytesWithoutSignature(withHash bool) []byte {

	b := tx.TxParam.GetBytes()
	bd, err := tx.TxData.GetBytes()
	if err != nil {
		return nil
	}
	b = append(b, bd...)
	b = append(b, common.GetByteInt64(tx.Height)...)
	b = append(b, common.GetByteInt64(tx.GasPrice)...)
	b = append(b, common.GetByteInt64(tx.GasUsage)...)
	if withHash {
		b = append(b, tx.GetHash().GetBytes()...)
	}
	return b
}

func (mt *Transaction) CalcHashAndSet() error {
	b := mt.GetBytesWithoutSignature(false)
	hash, err := common.CalcHashFromBytes(b)
	if err != nil {
		return err
	}
	mt.Hash = hash
	return nil
}

func (mt *Transaction) GetBytes() []byte {
	if mt != nil {
		b := mt.GetBytesWithoutSignature(true)
		sb := common.BytesToLenAndBytes(mt.GetSignature().GetBytes())
		b = append(b, sb...)
		b = append(b, mt.ContractAddress.GetBytes()...)
		olb := common.BytesToLenAndBytes(mt.OutputLogs)
		b = append(b, olb...)

		return b
	}
	return nil
}

func (mt *Transaction) StoreToDBPoolTx(prefix []byte) error {
	prefix = append(prefix, mt.GetHash().GetBytes()...)
	bt := mt.GetBytes()
	if len(bt) == 0 {
		return fmt.Errorf("transaction has no body. storing fails: StoreToDBPoolTx")
	}
	err := database.MainDB.Put(prefix, bt)
	if err != nil {
		return err
	}
	return nil
}

func (mt *Transaction) RemoveFromDBPoolTx(prefix []byte) error {
	prefix = append(prefix, mt.GetHash().GetBytes()...)
	err := database.MainDB.Delete(prefix)
	if err != nil {
		return err
	}
	return nil
}

func RemoveTransactionFromDBbyHash(prefix []byte, hash []byte) error {
	prefix = append(prefix, hash...)
	err := database.MainDB.Delete(prefix)
	if err != nil {
		return err
	}
	return nil
}

func LoadFromDBPoolTx(prefix []byte, hashTransaction []byte) (Transaction, error) {
	prefix2 := append(prefix, hashTransaction...)
	bt, err := database.MainDB.Get(prefix2)
	if err != nil {
		return Transaction{}, err
	}
	if len(bt) == 0 {
		err = database.MainDB.Delete(prefix2)
		if err != nil {
			return Transaction{}, err
		}
		return Transaction{}, fmt.Errorf("in database transaction has no bytes stored: %v", hashTransaction)
		//logger.GetLogger().Println("in database transaction has no bytes stored")
	}
	mt := &Transaction{}
	at, restb, err := mt.GetFromBytes(bt)
	if err != nil {
		return Transaction{}, err
	}
	if len(restb) > 0 {
		logger.GetLogger().Println("len(restb)", len(restb))
	}
	return at, nil
}

func CheckFromDBPoolTx(prefix []byte, hashTransaction []byte) bool {
	prefix = append(prefix, hashTransaction...)
	isKey, err := database.MainDB.IsKey(prefix)
	if err != nil {
		return false
	}
	return isKey
}

// Verify - checking if hash is correct and signature
func (tx *Transaction) Verify(sigName, sigName2 string, isPausedTmp, isPaused2Tmp bool) bool {
	recipientAddress := tx.TxData.Recipient
	n, err := account.IntDelegatedAccountFromAddress(recipientAddress)
	// Nonce transactions (delegated account recipient with zero amount) and genesis transactions are exempt from gas fees
	isNonceTx := err == nil && n > 0 && n < 256 && tx.GetData().Amount == 0
	isGenesisTx := tx.Height == 0
	// AC-H3: reject transactions carrying a foreign chain ID to prevent
	// cross-chain replay (e.g. testnet txs replayed on mainnet). Genesis txs are
	// exempt, matching the fee-exemption handling below.
	if !isGenesisTx && tx.TxParam.ChainID != common.GetChainID() {
		logger.GetLogger().Println("transaction chain ID mismatch: expected", common.GetChainID(), "got", tx.TxParam.ChainID)
		return false
	}
	if !isNonceTx && !isGenesisTx {
		if tx.GasPrice <= 0 {
			logger.GetLogger().Println("transaction gas price must be greater than 0")
			return false
		}
		if tx.GasUsage < tx.GasUsageEstimate() {
			logger.GetLogger().Println("transaction gas usage must be at least ", tx.GasUsageEstimate())
			return false
		}
	}
	if tx.GetData().Amount < 0 && err != nil && n < 512 {
		logger.GetLogger().Println("transaction amount has to be larger or equal 0")
		return false
	}
	// If operator staking transaction, verify both pubkeys are registered
	if n > 0 && n < 256 && len(tx.TxData.OptData) > 0 && tx.GetData().Amount > 0 {
		senderAddr := tx.GetSenderAddress()
		addresses, addrErr := pubkeys.LoadAddresses(senderAddr)
		if addrErr != nil {
			logger.GetLogger().Println("operator must have registered pubkeys: Verify")
			return false
		}
		hasPrimary := false
		hasSecondary := false
		for _, addr := range addresses {
			if addr.Primary {
				hasPrimary = true
			} else {
				hasSecondary = true
			}
		}
		if !hasPrimary || !hasSecondary {
			logger.GetLogger().Println("operator must have both primary and secondary pubkeys registered: Verify")
			return false
		}
	}
	if tx.GetLockedAmount() > 0 {
		n, err := account.IntDelegatedAccountFromAddress(tx.GetDelegatedAccountForLocking())

		if n < 0 || n > 256 || err != nil {
			logger.GetLogger().Println("transaction locking must have delegated account properly set")
			return false
		}
		if tx.GetLockedAmount() < 0 {
			logger.GetLogger().Println("transaction locked amount has to be larger or equal 0")
			return false
		}
		if tx.GetLockedAmount() > tx.GetData().Amount {
			logger.GetLogger().Println("transaction locked amount has to be less or equal amount")
			return false
		}
		if tx.GetReleasePerBlock() < 0 {
			logger.GetLogger().Println("transaction release amount per block has to be larger or equal 0")
			return false
		}
		if tx.GetReleasePerBlock() > tx.GetLockedAmount() {
			logger.GetLogger().Println("transaction release amount per block has to be less or equal locked amount")
			return false
		}
	}

	canAccountBeModified := account.CanBeModifiedAccount(tx.TxData.Recipient.GetBytes())

	if canAccountBeModified == false && (tx.TxData.EscrowTransactionsDelay > 0 || tx.TxData.MultiSignNumber > 0) {
		logger.GetLogger().Println("Account cannot be modified")
		return false
	}

	//escrow check
	if tx.TxData.EscrowTransactionsDelay > 0 {
		if tx.TxData.EscrowTransactionsDelay > common.MaxTransactionDelay {
			logger.GetLogger().Println("transaction delay has to be less than ", common.MaxTransactionDelay)
			return false
		}
	} else if tx.TxData.EscrowTransactionsDelay < 0 {
		logger.GetLogger().Println("transaction delay must be larger than 0")
		return false
	}

	// multisign check
	if tx.TxData.MultiSignNumber > 0 {
		if int(tx.TxData.MultiSignNumber) > len(tx.TxData.MultiSignAddresses) {
			logger.GetLogger().Println("number of signatures cannot overflow number of defined addresses in multi sign account")
			return false
		}
	}
	b := tx.GetHash().GetBytes()
	err = tx.CalcHashAndSet()
	if err != nil {
		return false
	}
	// logger.GetLogger().Println("transaction hash: ", tx.GetHash().GetHex())
	if !bytes.Equal(b, tx.GetHash().GetBytes()) {
		logger.GetLogger().Println("check transaction hash fails")
		return false
	}
	signature := tx.GetSignature()
	primary := signature.GetBytes()[0] == 0

	pk := tx.TxData.GetPubKey()
	pkb := pk.GetBytes()
	if len(pkb) == 0 {
		senderAddr := tx.GetSenderAddress()
		// Prefer the sender key whose length matches the scheme this signature
		// is verified under: after a scheme change the newest registered key
		// belongs to the new scheme, while a signature made earlier (an oracle
		// proof verified against the config at its signing height) needs the
		// superseded key it was made with.
		schemeName := sigName
		if !primary {
			schemeName = sigName2
		}
		var pkp common.PubKey
		expLen, lenErr := oqs.PubKeyLength(schemeName)
		if lenErr != nil {
			// The scheme is not one liboqs knows, so its key length is unknown
			// and no length-matched lookup is possible. Best effort: take the
			// newest key registered in this slot.
			var err error
			pkp, err = pubkeys.LoadPubKeyWithPrimary(senderAddr, primary)
			if err != nil {
				logger.GetLogger().Println("Verify: cannot load sender pubkey from DB:", err)
				logger.GetLogger().Println("  Sender address:", senderAddr.GetHex())
				logger.GetLogger().Println("  Primary flag:", primary)
				return false
			}
		} else {
			var err error
			pkp, err = pubkeys.LoadPubKeyWithPrimaryOfLength(senderAddr, primary, expLen)
			if err != nil {
				// Deliberately NOT falling back to "any key in this slot". Key
				// length identifies the scheme here, so a key of a different
				// length cannot verify a signature made under this one — the
				// fallback could only ever produce a rejection, while replacing
				// the real reason with an obscure "LengthPublicKey: 1793
				// len(pubkey): 897" from the verifier.
				//
				// This is what a signature-scheme change looks like before the
				// new key has been registered on-chain: registration happens
				// only when the operator sends a transaction carrying the
				// pubkey, and until then nothing this account signs can be
				// verified by anyone.
				logger.GetLogger().Printf("Verify: sender %s has no registered %s key (%d bytes) in the %s slot; "+
					"the key for the current scheme must be registered by sending a transaction that carries the pubkey: %v",
					senderAddr.GetHex(), schemeName, expLen, map[bool]string{true: "primary", false: "secondary"}[primary], err)
				return false
			}
		}
		pkb = pkp.GetBytes()
	} else {
		// If pubkey is included in transaction, verify it matches the sender address
		senderAddr := tx.GetSenderAddress()
		logger.GetLogger().Println("Verify: pubkey included in transaction")
		logger.GetLogger().Println("  PubKey bytes length:", len(pkb))
		logger.GetLogger().Println("  Sender address:", senderAddr.GetHex())
		logger.GetLogger().Println("  Signature primary flag:", primary)
		logger.GetLogger().Println("  PubKey.Primary field:", pk.Primary)
		// PubKey.Primary is DERIVED from the key length by PubKey.Init, so a
		// "false" on a key that ought to be primary means the key does not
		// belong to the scheme currently in the primary slot. Print what that
		// slot expects, so the mismatch is stated instead of inferred.
		logger.GetLogger().Printf("  schemes in force: primary=%s (%d-byte key), secondary=%s (%d-byte key); paused=[%v/%v]",
			sigName, common.PubKeyLength(false), sigName2, common.PubKeyLength2(false), isPausedTmp, isPaused2Tmp)

		// Use the pubkey's own Primary flag for address derivation
		pkPrimary := pk.Primary
		pkAddr, err := common.PubKeyToAddress(pkb, pkPrimary)
		if err != nil {
			logger.GetLogger().Println("  ERROR: cannot derive address from pubkey:", err)
			return false
		}
		logger.GetLogger().Println("  Derived address:", pkAddr.GetHex())
		logger.GetLogger().Println("  PubKey.MainAddress:", pk.MainAddress.GetHex())

		// Which identity a key belongs to is ON-CHAIN state, so read it from the
		// key registry rather than believing what the transaction asserts.
		// LoadPubKey resolves the key's own derived address to the record stored
		// when it was registered, and that record's MainAddress is the binding
		// consensus already agreed on.
		//
		// This matters beyond tidiness. The pk.MainAddress field travels inside
		// the transaction, so taking it at face value let a sender nominate any
		// identity it liked for a key it controls; the registry cannot be talked
		// into a claim it never recorded.
		//
		// It also handles the case the derived-address rule could not express: a
		// key of a NEWLY voted-in scheme has an address of its own, different
		// from the identity it serves, exactly as a secondary key always has.
		addressMatch := false
		resolvedFromRegistry := false
		if stored, lerr := pubkeys.LoadPubKey(pkAddr.GetBytes()); lerr == nil {
			addressMatch = bytes.Equal(stored.MainAddress.GetBytes(), senderAddr.GetBytes())
			resolvedFromRegistry = true
			logger.GetLogger().Println("  registry says this key belongs to:", stored.MainAddress.GetHex())
		}
		if !resolvedFromRegistry {
			// The key is new: there is no recorded binding, so the transaction
			// has to demonstrate authority over the identity it names.
			//
			// It does that by being SIGNED WITH A KEY ALREADY REGISTERED under
			// that identity, while the new key rides along as data. Signing with
			// the enclosed key would prove only that the sender owns that key,
			// which is no argument for attaching it to somebody's identity.
			//
			// This is also the only way a new PRIMARY key can ever be introduced:
			// a scheme replacement arrives paused, so the incoming primary
			// cannot sign anything — the spare, live exactly while the primary
			// is paused, is what authorises it.
			signingScheme := sigName
			if !primary {
				signingScheme = sigName2
			}
			authorised := false
			if expLen, lerr := oqs.PubKeyLength(signingScheme); lerr == nil {
				if existing, aerr := pubkeys.LoadPubKeyWithPrimaryOfLength(senderAddr, primary, expLen); aerr == nil {
					// Verify the signature against the REGISTERED key, not the
					// enclosed one.
					pkb = existing.GetBytes()
					addressMatch = bytes.Equal(pk.MainAddress.GetBytes(), senderAddr.GetBytes())
					authorised = true
					logger.GetLogger().Printf("  new key introduced by identity %s, authorised by its registered %s key",
						senderAddr.GetHex(), signingScheme)
				}
			}
			if !authorised {
				// Nothing is registered for this sender yet, so there is no
				// identity to authorise anything: the very first key can only
				// vouch for itself, and the sole claim a key can prove on its
				// own is to the address it derives.
				//
				// The previous rule let a NON-DERIVING key bootstrap an
				// identity on the strength of pk.MainAddress alone. That field
				// is an assertion carried inside the transaction and proved by
				// nothing, so enclosing your own spare key while naming
				// somebody else's address bound your key to their identity:
				// from then on LoadPubKey resolved it to them and your
				// signature spent their coins. Registration is not a
				// prerequisite for holding a balance, so every funded account
				// that had not yet registered a key was takeable by anyone who
				// knew its address.
				//
				// One consequence is deliberate and worth stating: an
				// identity's FIRST on-chain key must be the key that derives
				// it. A spare cannot open an account. Because the spare is live
				// exactly while the primary is paused, no identity can be
				// bootstrapped during a pause — a transient governance state,
				// and the alternative is an unprovable claim. Every LATER key,
				// including an entire new scheme's after a replacement, arrives
				// through the authorised path above: signed by a key already
				// registered to that identity.
				logger.GetLogger().Println("  sender has no registered key for the signing scheme; bootstrap rule applies (the key must derive the sender address)")
				addressMatch = bootstrapBindsKey(pkAddr, senderAddr)
				if !addressMatch && !pkPrimary {
					logger.GetLogger().Println("  a spare key cannot open an account: register the key that derives this address first, " +
						"while its scheme is not paused, then introduce further keys by signing with it")
				}
			}
		}

		// Whichever branch established authority, the key must also NAME the
		// sender as its identity. This is a separate question from who is
		// allowed to register it, and it needs its own check because
		// ProcessBlockPubKey stores pk.MainAddress verbatim without consulting
		// the sender: a key admitted while naming somebody else would be
		// recorded against them, which is the same account takeover by a
		// different route.
		if addressMatch && !keyNamesSender(pk.MainAddress, senderAddr) {
			logger.GetLogger().Println("  ERROR: the enclosed key names an identity other than the sender")
			logger.GetLogger().Println("  PubKey.MainAddress:", pk.MainAddress.GetHex())
			logger.GetLogger().Println("  Expected (sender):", senderAddr.GetHex())
			return false
		}

		if !addressMatch {
			logger.GetLogger().Println("  ERROR: pubkey address mismatch!")
			logger.GetLogger().Println("  Derived:", pkAddr.GetHex())
			logger.GetLogger().Println("  Expected (sender):", senderAddr.GetHex())
			if !pkPrimary {
				logger.GetLogger().Println("  PubKey.MainAddress:", pk.MainAddress.GetHex())
			}
			return false
		}
		logger.GetLogger().Println("  Address verification OK")

		// The enclosed key is DATA — the key being registered. What SIGNED the
		// transaction is a separate question, answered by the signature's own
		// scheme flag, and the two differ in the case that matters: a key
		// arrives paused and cannot sign for itself, so the live scheme signs
		// for it.
		//
		// Verify against a key of the SIGNING scheme, therefore, not against
		// whatever was enclosed. Using the enclosed key produced the misleading
		// "LengthPublicKey: 66576 len(pubkey): 1793" — a signature made with the
		// spare checked against the primary's key.
		if expLen, lerr := oqs.PubKeyLength(signingSchemeName(primary, sigName, sigName2)); lerr == nil && len(pkb) != expLen {
			signer, serr := pubkeys.LoadPubKeyWithPrimaryOfLength(senderAddr, primary, expLen)
			if serr != nil {
				logger.GetLogger().Printf("  cannot verify: the transaction is signed with %s but sender %s has no registered %s key (%d bytes): %v",
					signingSchemeName(primary, sigName, sigName2), senderAddr.GetHex(),
					signingSchemeName(primary, sigName, sigName2), expLen, serr)
				return false
			}
			logger.GetLogger().Printf("  enclosed key is the one being registered; verifying the signature against the sender's registered %s key",
				signingSchemeName(primary, sigName, sigName2))
			pkb = signer.GetBytes()
		}
		// Store pubkey immediately so it's available for nonce verification
		// storePubKeyImmediately(pk, senderAddr)
	}
	//logger.GetLogger().Println(sigName, sigName2, isPausedTmp, isPaused2Tmp)
	return wallet.Verify(b, signature.GetBytes(), pkb, sigName, sigName2, isPausedTmp, isPaused2Tmp)
}

// bootstrapBindsKey reports whether a key with no on-chain history may open the
// identity that sent it. Only a key that DERIVES that address can: the address
// is a hash of the key, so holding the key is itself the proof, and no other
// claim a first key could make is backed by anything.
//
// In particular a spare key cannot open an account. Its address differs from
// the identity by construction, so accepting it would mean believing the
// transaction's own assertion about whose key it is.
func bootstrapBindsKey(pkAddr, senderAddr common.Address) bool {
	return bytes.Equal(pkAddr.GetBytes(), senderAddr.GetBytes())
}

// keyNamesSender reports whether an enclosed key claims the sender as its
// identity. Required however the key earned the right to be registered:
// ProcessBlockPubKey stores the claimed identity verbatim, so a key admitted
// while naming somebody else is recorded against them and its holder can then
// sign as them.
func keyNamesSender(pkMainAddress, senderAddr common.Address) bool {
	return bytes.Equal(pkMainAddress.GetBytes(), senderAddr.GetBytes())
}

// signingSchemeName returns the scheme a signature was made under, chosen by
// the flag the signature carries rather than by anything the transaction body
// claims.
func signingSchemeName(primary bool, sigName, sigName2 string) string {
	if primary {
		return sigName
	}
	return sigName2
}

func (tx *Transaction) Sign(w *wallet.Wallet, primary bool) error {
	b := tx.GetHash()
	sign, err := w.Sign(b.GetBytes(), primary)
	if err != nil {
		return err
	}
	tx.Signature = *sign
	return nil
}

func EmptyTransaction() Transaction {
	tx := Transaction{
		TxData: TxData{
			Recipient: common.EmptyAddress(),
			Amount:    0,
			OptData:   []byte{},
		},
		TxParam: TxParam{
			ChainID:     0,
			Sender:      common.EmptyAddress(),
			SendingTime: 0,
			Nonce:       0,
		},
		Hash:      common.EmptyHash(),
		Signature: common.Signature{},
		Height:    0,
		GasPrice:  0,
		GasUsage:  0,
	}
	err := tx.CalcHashAndSet()
	if err != nil {
		logger.GetLogger().Println("empty transaction calc hash fails")
	}
	tx.Signature = common.EmptySignature()
	return tx
}

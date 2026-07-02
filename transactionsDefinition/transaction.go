package transactionsDefinition

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/pubkeys"
	"github.com/wonabru/qwid-node/wallet"
)

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

func (tx *Transaction) GetFromBytes(b []byte) (Transaction, []byte, error) {

	if len(b) < 76+common.SignatureLength(true)+1 && len(b) < 76+common.SignatureLength2(true)+1 {
		return Transaction{}, nil, fmt.Errorf("Not enough bytes for transaction unmarshal len bytes %v", len(b))
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
	at := Transaction{
		TxData:    adata,
		TxParam:   tp,
		Hash:      common.Hash{},
		Signature: common.Signature{},
		Height:    common.GetInt64FromByte(b[:8]),
		GasPrice:  common.GetInt64FromByte(b[8:16]),
		GasUsage:  common.GetInt64FromByte(b[16:24]),
	}
	at.Hash = common.GetHashFromBytes(b[24:56])
	vb, leftb, err := common.BytesWithLenToBytes(b[56:])
	if err != nil {
		return Transaction{}, nil, err
	}
	signature, err := common.GetSignatureFromBytes(vb, tp.Sender)
	if err != nil {
		return Transaction{}, nil, err
	}
	at.Signature = signature
	err = at.ContractAddress.Init(leftb[:20])
	if err != nil {
		return Transaction{}, nil, err
	}
	toBytes, leftb2, err := common.BytesWithLenToBytes(leftb[20:])
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
		pkp, err := pubkeys.LoadPubKeyWithPrimary(senderAddr, primary)
		if err != nil {
			logger.GetLogger().Println("Verify: cannot load sender pubkey from DB:", err)
			logger.GetLogger().Println("  Sender address:", senderAddr.GetHex())
			logger.GetLogger().Println("  Primary flag:", primary)
			return false
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

		// Use the pubkey's own Primary flag for address derivation
		pkPrimary := pk.Primary
		pkAddr, err := common.PubKeyToAddress(pkb, pkPrimary)
		if err != nil {
			logger.GetLogger().Println("  ERROR: cannot derive address from pubkey:", err)
			return false
		}
		logger.GetLogger().Println("  Derived address:", pkAddr.GetHex())
		logger.GetLogger().Println("  PubKey.MainAddress:", pk.MainAddress.GetHex())

		// For primary pubkey: derived address should match sender address directly
		// For secondary pubkey: MainAddress (which equals the wallet's main/primary address) should match sender
		addressMatch := false
		if pkPrimary {
			// Primary pubkey: derived address should equal sender address
			addressMatch = bytes.Equal(pkAddr.GetBytes(), senderAddr.GetBytes())
		} else {
			// Secondary pubkey: the pubkey's MainAddress should equal sender address
			// (MainAddress is the wallet's primary address that both accounts share)
			addressMatch = bytes.Equal(pk.MainAddress.GetBytes(), senderAddr.GetBytes())
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
		// Store pubkey immediately so it's available for nonce verification
		// storePubKeyImmediately(pk, senderAddr)
	}
	//logger.GetLogger().Println(sigName, sigName2, isPausedTmp, isPaused2Tmp)
	return wallet.Verify(b, signature.GetBytes(), pkb, sigName, sigName2, isPausedTmp, isPaused2Tmp)
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


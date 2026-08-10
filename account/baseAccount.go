package account

import (
	"bytes"
	"fmt"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/common/hexutil"
	"github.com/qwid-org/qwid-node/logger"
	"math"
	"strconv"
)

type Account struct {
	Balance            int64                        `json:"balance"`
	Address            [common.AddressLength]byte   `json:"address"`
	TransactionDelay   int64                        `json:"transactionDelay"`
	MultiSignNumber    uint8                        `json:"multiSignNumber"`
	MultiSignAddresses [][common.AddressLength]byte `json:"multiSignAddresses,omitempty"`
	// TransactionsSender/TransactionsRecipient no longer live in the account
	// state. They grew by one hash per transaction forever, which made every
	// state snapshot marshal O(chain history) - at height ~100k that was ~2s
	// of pure serialization per snapshot. The full history now lives in a
	// DB-side index (txHistory.go) keyed by (address, sequence); the state
	// keeps only the two sequence counters below. The slices remain as a
	// transport container: the RPC layer fills them from the index for
	// wallet/explorer responses, and Unmarshal fills them when reading a
	// pre-index snapshot (LoadAccounts then migrates them into the index).
	TransactionsSender    []common.Hash `json:"transactionsSender,omitempty"`
	TransactionsRecipient []common.Hash `json:"transactionsRecipient,omitempty"`
	// SentCount/ReceivedCount are the lengths of this account's history in the
	// index. They are part of the state snapshot ON PURPOSE: a rewind restores
	// the counters, and subsequent re-applied transactions overwrite the index
	// entries above them - which rolls the visible history back without ever
	// scanning the index.
	SentCount     int64 `json:"sentCount,omitempty"`
	ReceivedCount int64 `json:"receivedCount,omitempty"`
}

func GetAccountByAddressBytes(address []byte) (Account, bool) {
	AccountsRWMutex.RLock()
	defer AccountsRWMutex.RUnlock()
	addrb := [common.AddressLength]byte{}
	copy(addrb[:], address[:common.AddressLength])
	acc, ok := Accounts.AllAccounts[addrb]
	return acc, ok
}

func CanBeModifiedAccount(address []byte) bool {
	acc, exist := GetAccountByAddressBytes(address)
	if exist {
		return acc.MultiSignNumber == 0 && acc.TransactionDelay == 0
	} else {
		return false
	}
}

func (a *Account) ModifyAccountToEscrow(transactionDelay int64) error {
	if a.TransactionDelay > 0 {
		return fmt.Errorf("account is already escrow and cannot be modified")
	}
	if a.MultiSignNumber > 0 {
		return fmt.Errorf("account is multisign and cannot be converted to escrow")
	}
	if transactionDelay == 0 {
		return fmt.Errorf("transaction delay in escrow must be larger than 0")
	}
	if transactionDelay > common.MaxTransactionDelay {
		return fmt.Errorf("transaction delay in escrow must be less than %v", common.MaxTransactionDelay)
	}
	a.TransactionDelay = transactionDelay
	AccountsRWMutex.Lock()
	Accounts.AllAccounts[a.Address] = *a
	AccountsRWMutex.Unlock()
	return nil
}

func (a *Account) ModifyAccountToMultiSign(numApprovals uint8, addresses []common.Address) error {
	if a.MultiSignNumber > 0 {
		return fmt.Errorf("account is already multisign and cannot be modified")
	}
	if a.TransactionDelay > 0 {
		return fmt.Errorf("account is escrow and cannot be converted to multisign")
	}
	if int(numApprovals) == 0 {
		return fmt.Errorf("MultiSign must have at least 1 Approval account")
	}
	if int(numApprovals) > len(addresses) {
		return fmt.Errorf("number of MultiSign approval addresses must be larger than number of Approvals %v", numApprovals)
	}
	a.MultiSignNumber = numApprovals

	addrs := make([][common.AddressLength]byte, len(addresses))
	for i, a := range addresses {
		copy(addrs[i][:], a.GetBytes())
	}
	a.MultiSignAddresses = addrs
	AccountsRWMutex.Lock()
	Accounts.AllAccounts[a.Address] = *a
	AccountsRWMutex.Unlock()
	return nil
}

func SetAccountByAddressBytes(address []byte) Account {
	account, exist := GetAccountByAddressBytes(address)
	if !exist {
		logger.GetLogger().Println("no account found, will be created")
		addrb := [common.AddressLength]byte{}
		copy(addrb[:], address[:common.AddressLength])
		account = Account{
			Balance:               0,
			Address:               addrb,
			TransactionDelay:      0,
			MultiSignNumber:       0,
			TransactionsSender:    make([]common.Hash, 0),
			TransactionsRecipient: make([]common.Hash, 0),
		}
		AccountsRWMutex.Lock()
		Accounts.AllAccounts[addrb] = account
		AccountsRWMutex.Unlock()
	}
	if !bytes.Equal(account.Address[:], address) {
		logger.GetLogger().Println("WARNING: account has wrong address set. Rewrite address")
		copy(account.Address[:], address)
	}
	return account
}

// GetBalanceConfirmedFloat get amount of confirmed KURA in human-readable format
func (a *Account) GetBalanceConfirmedFloat() float64 {
	return float64(a.Balance) * math.Pow10(-int(common.Decimals))
}

func (a Account) Marshal() []byte {
	b := common.GetByteInt64(a.Balance)
	b = append(b, a.Address[:]...)
	delay := common.GetByteInt64(a.TransactionDelay)
	b = append(b, delay...)
	b = append(b, a.MultiSignNumber)
	b = append(b, byte(len(a.MultiSignAddresses)))
	for _, msa := range a.MultiSignAddresses {
		b = append(b, msa[:]...)
	}
	nts := common.GetByteInt64(int64(len(a.TransactionsSender)))
	b = append(b, nts...)
	for _, txHash := range a.TransactionsSender {
		b = append(b, txHash.GetBytes()...)
	}
	ntr := common.GetByteInt64(int64(len(a.TransactionsRecipient)))
	b = append(b, ntr...)
	for _, txHash := range a.TransactionsRecipient {
		b = append(b, txHash.GetBytes()...)
	}
	// Appended for backward-compatible decoding: pre-index snapshots end after
	// the recipient list, and Unmarshal then derives the counters from the
	// list lengths instead.
	b = append(b, common.GetByteInt64(a.SentCount)...)
	b = append(b, common.GetByteInt64(a.ReceivedCount)...)
	return b
}

func (a *Account) Unmarshal(data []byte) error {
	if len(data) < 38 {
		return fmt.Errorf("wrong number of bytes in unmarshal account %v", len(data))
	}
	a.Balance = common.GetInt64FromByte(data[:8])

	copy(a.Address[:], data[8:28])
	a.TransactionDelay = common.GetInt64FromByte(data[28:36])
	a.MultiSignNumber = data[36]
	msa := data[37]
	data = data[38:]
	// MultiSignAddresses
	if msa > 0 {
		// check if enough data
		if len(data) < int(msa)*20 {
			return fmt.Errorf("not enough data for multisign addresses: need %d, have %d", int(msa)*20, len(data))
		}

		a.MultiSignAddresses = make([][common.AddressLength]byte, msa)
		for i := 0; i < int(msa); i++ {
			copy(a.MultiSignAddresses[i][:], data[:20])
			data = data[20:]
		}
	}

	if len(data) >= 16 {
		nts := common.GetInt64FromByte(data[:8])
		data = data[8:]
		// check if enough data
		if len(data) < int(nts)*32 {
			return fmt.Errorf("not enough data for sender transactions: need %d, have %d", int(nts)*32, len(data))
		}

		a.TransactionsSender = make([]common.Hash, nts)
		for i := int64(0); i < nts; i++ {
			th := common.Hash{}
			copy(th[:], data[:32])
			a.TransactionsSender[i] = th
			data = data[32:]
		}
		ntr := common.GetInt64FromByte(data[:8])
		data = data[8:]
		// check if enough data
		if len(data) < int(ntr)*32 {
			return fmt.Errorf("not enough data for recipient transactions: need %d, have %d", int(nts)*32, len(data))
		}
		a.TransactionsRecipient = make([]common.Hash, ntr)
		for i := int64(0); i < ntr; i++ {
			th := common.Hash{}
			copy(th[:], data[:32])
			a.TransactionsRecipient[i] = th
			data = data[32:]
		}
	}
	// History counters. A pre-index snapshot ends right after the lists; its
	// full history IS the lists, so the counters equal their lengths and
	// LoadAccounts migrates the hashes into the DB index afterwards.
	if len(data) >= 16 {
		a.SentCount = common.GetInt64FromByte(data[:8])
		a.ReceivedCount = common.GetInt64FromByte(data[8:16])
	} else {
		a.SentCount = int64(len(a.TransactionsSender))
		a.ReceivedCount = int64(len(a.TransactionsRecipient))
	}
	return nil
}

func (a Account) GetString() string {
	r := "Address: " + hexutil.Encode(a.Address[:]) + "\n"
	r += "Balance: " + strconv.FormatInt(a.Balance, 10) + "\n"
	if a.TransactionDelay > 0 {
		r += "Escrow account with "
		r += "Transactions Delayed: " + strconv.FormatInt(a.TransactionDelay, 10) + " blocks\n"
	}
	if a.MultiSignNumber > 0 {
		r += "Multi Signature account with \n"
		r += "Signatures: " + strconv.FormatInt(int64(a.MultiSignNumber), 10) + "/" + strconv.FormatInt(int64(len(a.MultiSignAddresses)), 10) + "\n"
		r += "Multi Signature Addresses: \n"
		for i, msa := range a.MultiSignAddresses {
			r += "\t" + strconv.FormatInt(int64(i), 10) + ": " + hexutil.Encode(msa[:]) + "\n"
		}
	}
	if len(a.TransactionsSender) > 0 {
		r += "Sent Transactions: \n"
		for _, txnHash := range a.TransactionsSender {
			r += txnHash.GetHex() + "\n"
		}
	}
	if len(a.TransactionsRecipient) > 0 {
		r += "Received Transactions: \n"
		for _, txnHash := range a.TransactionsRecipient {
			r += txnHash.GetHex() + "\n"
		}
	}
	return r
}

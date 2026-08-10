package transactionsDefinition

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/common/hexutil"
	"strconv"
)

type TxData struct {
	Recipient                  common.Address               `json:"recipient"`
	Amount                     int64                        `json:"amount"`
	OptData                    []byte                       `json:"opt_data,omitempty"`
	Pubkey                     common.PubKey                `json:"pubkey,omitempty"`
	LockedAmount               int64                        `json:"lockedAmount,omitempty"`
	ReleasePerBlock            int64                        `json:"releasePerBlock,omitempty"`
	DelegatedAccountForLocking common.Address               `json:"delegatedAccountForLocking,omitempty"`
	EscrowTransactionsDelay    int64                        `json:"escrowTransactionsDelay,omitempty"`
	MultiSignNumber            uint8                        `json:"multiSignNumber,omitempty"`
	MultiSignAddresses         [][common.AddressLength]byte `json:"multiSignAddresses,omitempty"`
}

func (td TxData) GetString() string {
	t := "Recipient: " + td.Recipient.GetHex() + "\n"
	t += "Amount QWD: " + fmt.Sprintln(account.Int64toFloat64(td.Amount)) + "\n"
	t += "Opt Data: " + hex.EncodeToString(td.OptData) + "\n"
	if td.Pubkey.ByteValue != nil {
		t += "Pubkey: " + td.Pubkey.GetHex()[:20] + "\n"
	}
	t += "Address: " + td.Pubkey.Address.GetHex() + "\n"
	if td.LockedAmount > 0 {
		t += "Locked Amount: " + fmt.Sprintln(account.Int64toFloat64(td.LockedAmount)) + "\n"
		t += "Release Per Block: " + fmt.Sprintln(account.Int64toFloat64(td.ReleasePerBlock)) + "\n"
		t += "Delegated Account for Locking: " + td.DelegatedAccountForLocking.GetHex() + "\n"
	}
	if td.EscrowTransactionsDelay > 0 {
		t += "Escrow account modification with delay: " + strconv.FormatInt(td.EscrowTransactionsDelay, 10) + " blocks\n"
	}
	if td.MultiSignNumber > 0 {
		t += "Multi Signature account with \n"
		t += "Signatures: " + strconv.FormatInt(int64(td.MultiSignNumber), 10) + "/" + strconv.FormatInt(int64(len(td.MultiSignAddresses)), 10) + "\n"
		t += "Multi Signature Addresses: \n"
		for i, msa := range td.MultiSignAddresses {
			t += "\t" + strconv.FormatInt(int64(i), 10) + ": " + hexutil.Encode(msa[:]) + "\n"
		}
	}
	return t
}

func (md TxData) GetOptData() []byte {
	return md.OptData
}
func (md TxData) GetAmount() int64 {
	return md.Amount
}
func (md TxData) GetRecipient() common.Address {
	return md.Recipient
}
func (md TxData) GetAddress() common.Address {
	return md.Pubkey.Address
}
func (md TxData) GetPubKey() common.PubKey {
	return md.Pubkey
}
func (md Transaction) GetLockedAmount() int64 {
	return md.TxData.LockedAmount
}
func (md Transaction) GetReleasePerBlock() int64 {
	return md.TxData.ReleasePerBlock
}
func (md Transaction) GetDelegatedAccountForLocking() common.Address {
	return md.TxData.DelegatedAccountForLocking
}

func (md TxData) GetBytes() ([]byte, error) {
	b := md.Recipient.GetBytesWithPrimary()
	b = append(b, common.GetByteInt64(md.Amount)...)
	bl := []byte{}
	opt := common.BytesToLenAndBytes(md.OptData)
	bl = append(bl, opt...)
	adb := common.BytesToLenAndBytes(md.Pubkey.MainAddress.GetBytesWithPrimary())
	bl = append(bl, adb...)
	pk := common.BytesToLenAndBytes(md.Pubkey.GetBytes())
	bl = append(bl, pk...)
	bl = append(bl, common.BytesToLenAndBytes(common.GetByteInt64(md.LockedAmount))...)
	bl = append(bl, common.BytesToLenAndBytes(common.GetByteInt64(md.ReleasePerBlock))...)
	bl = append(bl, common.BytesToLenAndBytes(md.DelegatedAccountForLocking.GetBytes())...)
	bl = append(bl, common.BytesToLenAndBytes(common.GetByteInt64(md.EscrowTransactionsDelay))...)
	bl = append(bl, common.BytesToLenAndBytes([]byte{md.MultiSignNumber})...)
	for _, msa := range md.MultiSignAddresses {
		bl = append(bl, common.BytesToLenAndBytes(msa[:])...)
	}
	// one can check if bl is only zeros and omit this appending
	zeros := make([]byte, len(bl))
	if bytes.Equal(bl, zeros) == false {
		b = append(b, common.BytesToLenAndBytes(bl)...)
	}
	return b, nil
}

func (TxData) GetFromBytes(data []byte) (TxData, []byte, error) {
	md := TxData{}
	address, err := common.BytesToAddress(data[:common.AddressLength+1])
	if err != nil {
		return TxData{}, nil, err
	}
	md.Recipient = address
	amountBytes := data[common.AddressLength+1 : common.AddressLength+9]
	md.Amount = common.GetInt64FromByte(amountBytes)

	bl, leftBl, err := common.BytesWithLenToBytes(data[common.AddressLength+9:])
	if err != nil {
		return TxData{}, nil, err
	}
	zeros := make([]byte, len(bl))
	if bytes.Equal(bl, zeros) {
		return md, leftBl, nil
	}
	opt, left, err := common.BytesWithLenToBytes(bl)
	if err != nil {
		return TxData{}, nil, err
	}
	md.OptData = opt

	ma, left, err := common.BytesWithLenToBytes(left)
	mainAddress := common.Address{}
	err = mainAddress.Init(ma)
	zeros = make([]byte, len(ma[1:]))
	if err != nil && !bytes.Equal(ma[1:], zeros) {
		return TxData{}, nil, err
	}
	pk, left, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return TxData{}, nil, err
	}
	err = md.Pubkey.Init(pk, mainAddress)
	if err != nil && len(pk) > 0 {
		return TxData{}, nil, err
	}
	la, left, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return TxData{}, nil, err
	}
	md.LockedAmount = common.GetInt64FromByte(la)
	rpb, left, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return TxData{}, nil, err
	}
	md.ReleasePerBlock = common.GetInt64FromByte(rpb)
	dal, left, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return TxData{}, nil, err
	}
	md.DelegatedAccountForLocking, err = common.BytesToAddress(dal)
	if err != nil {
		return TxData{}, nil, err
	}

	etd, left, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return TxData{}, nil, err
	}
	md.EscrowTransactionsDelay = common.GetInt64FromByte(etd)

	msn, left, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return TxData{}, nil, err
	}
	md.MultiSignNumber = msn[0]

	if len(left) > 0 {
		lenAccMS := len(left) / 20
		if int(md.MultiSignNumber) > lenAccMS {
			return TxData{}, nil, fmt.Errorf("wrongly defined multisign account in transaction")
		}
		d := []byte{}
		if lenAccMS > 0 {
			md.MultiSignAddresses = make([][common.AddressLength]byte, lenAccMS)
			for i := 0; i < lenAccMS; i++ {
				d, left, err = common.BytesWithLenToBytes(left)
				if err != nil {
					return TxData{}, nil, err
				}
				copy(md.MultiSignAddresses[i][:], d)
			}
		}
	}

	return md, leftBl, nil
}

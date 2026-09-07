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
	// Length, not nil: a transaction with no key carries an empty slice after a
	// JSON round-trip, which is not nil and used to reach the truncation below.
	// Both lines describe the enclosed key, so both are omitted when there is
	// none. Address used to print unconditionally, and for a transaction
	// carrying no key it showed the address derived from an EMPTY key —
	// 3345524abf6bbe1809449224b5972c41790b6cf2, the same constant on every such
	// transaction. It names no account and reads as though the transfer touched
	// a third party.
	if len(td.Pubkey.ByteValue) > 0 {
		t += "Pubkey: " + common.HexPrefix(td.Pubkey.GetHex(), 20) + "\n"
		t += "Address derived from that key: " + td.Pubkey.Address.GetHex() + "\n"
	}
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

// txDataHeaderBytes is the recipient address (with its leading type byte) plus
// the 8-byte amount — everything TxData.GetFromBytes reads by fixed offset.
const txDataHeaderBytes = common.AddressLength + 9

func (TxData) GetFromBytes(data []byte) (TxData, []byte, error) {
	md := TxData{}
	// Bounds-check before the fixed-offset reads below. The caller's own length
	// check no longer covers this: it is a scheme-independent structural floor
	// (see minTransactionBytes), not a bound on what reaches this decoder after
	// the variable-length TxParam is consumed.
	if len(data) < txDataHeaderBytes {
		return TxData{}, nil, fmt.Errorf("not enough bytes in TxData unmarshaling %v < %v", len(data), txDataHeaderBytes)
	}
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
	if err != nil {
		// Previously the decode error was overwritten by Init below and never
		// checked, so a malformed length prefix left ma nil and the ma[1:]
		// slice panicked (QWID-2026-03).
		return TxData{}, nil, err
	}
	mainAddress := common.Address{}
	initErr := mainAddress.Init(ma)
	// The main-address field may legitimately be absent or all-zero (an
	// unchanged/unset identity); in that case Init returns an error we tolerate.
	// It is only a real error when the field actually carries a non-zero
	// address body. The body is ma minus its leading primary-flag byte — and ma
	// can be empty (attacker-chosen length 0), so strip the flag only when a
	// byte is present rather than slicing ma[1:] unconditionally.
	body := ma
	if len(body) > 0 {
		body = body[1:]
	}
	zeros = make([]byte, len(body))
	if initErr != nil && !bytes.Equal(body, zeros) {
		return TxData{}, nil, initErr
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
	// GetInt64FromByte panics on a slice shorter than 8, and every length here is
	// attacker-controlled: the encoder writes 8 bytes, a peer need not.
	if len(la) < 8 {
		return TxData{}, nil, fmt.Errorf("not enough bytes for locked amount in TxData: %v", len(la))
	}
	md.LockedAmount = common.GetInt64FromByte(la)
	rpb, left, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return TxData{}, nil, err
	}
	if len(rpb) < 8 {
		return TxData{}, nil, fmt.Errorf("not enough bytes for release per block in TxData: %v", len(rpb))
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
	if len(etd) < 8 {
		return TxData{}, nil, fmt.Errorf("not enough bytes for escrow delay in TxData: %v", len(etd))
	}
	md.EscrowTransactionsDelay = common.GetInt64FromByte(etd)

	msn, left, err := common.BytesWithLenToBytes(left)
	if err != nil {
		return TxData{}, nil, err
	}
	if len(msn) < 1 {
		return TxData{}, nil, fmt.Errorf("missing multisign number in TxData")
	}
	md.MultiSignNumber = msn[0]

	if len(left) > 0 {
		// Parse each signer entry until the sub-buffer is empty, rather than
		// pre-computing a count as len(left)/20. Every entry is a length-prefix
		// (4 bytes) plus a 20-byte address = 24 bytes, so the old quotient
		// over-counted from five entries up (120/20 = 6) and made every valid
		// 5+-signer definition fail to decode (QWID-2026-06). Parsing to
		// exhaustion consumes exactly the bytes the encoder wrote and decodes
		// one-to-four-signer definitions byte-for-byte as before, so no node
		// disagrees on any policy that exists today — the broken counts could
		// never have been created.
		var addrs [][common.AddressLength]byte
		for len(left) > 0 {
			var d []byte
			d, left, err = common.BytesWithLenToBytes(left)
			if err != nil {
				return TxData{}, nil, err
			}
			if len(d) != common.AddressLength {
				return TxData{}, nil, fmt.Errorf("multisign signer address must be %d bytes, got %d",
					common.AddressLength, len(d))
			}
			// MultiSignNumber is a byte, so the address list cannot exceed 255.
			if len(addrs) >= 255 {
				return TxData{}, nil, fmt.Errorf("too many multisign signer addresses")
			}
			var a [common.AddressLength]byte
			copy(a[:], d)
			addrs = append(addrs, a)
		}
		if int(md.MultiSignNumber) > len(addrs) {
			return TxData{}, nil, fmt.Errorf("multisign threshold %d exceeds the %d signer address(es)",
				md.MultiSignNumber, len(addrs))
		}
		md.MultiSignAddresses = addrs
	}

	return md, leftBl, nil
}

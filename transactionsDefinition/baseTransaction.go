package transactionsDefinition

import (
	"bytes"
	"fmt"
	"github.com/qwid-org/qwid-node/common"
	"strconv"
	"time"
)

type TxParam struct {
	ChainID     int16          `json:"chain_id"`
	Sender      common.Address `json:"sender"`
	SendingTime int64          `json:"sending_time"`
	// Nonce is int64 (AC-H2): int16 gave only 32768 values, weakening replay
	// protection. Widening changes the signed transaction layout and therefore
	// the chain genesis.
	Nonce       int64       `json:"nonce"`
	MultiSignTx common.Hash `json:"multi_sign_tx,omitempty"`
}

func (tp TxParam) GetBytes() []byte {

	b := common.GetByteInt16(tp.ChainID)
	b = append(b, tp.Sender.GetBytesWithPrimary()...)
	b = append(b, common.GetByteInt64(tp.SendingTime)...)
	b = append(b, common.GetByteInt64(tp.Nonce)...)
	b = append(b, common.BytesToLenAndBytes(tp.MultiSignTx.GetBytes())...)
	return b
}

func (tp TxParam) GetFromBytes(b []byte) (TxParam, []byte, error) {
	var err error
	if len(b) < 40 {
		return TxParam{}, []byte{}, fmt.Errorf("not enough bytes in TxParam unmarshaling %v < 40", len(b))
	}
	tp.ChainID = common.GetInt16FromByte(b[:2])
	tp.Sender, err = common.BytesToAddress(b[2:23])
	if err != nil {
		return TxParam{}, []byte{}, err
	}
	tp.SendingTime = common.GetInt64FromByte(b[23:31])
	tp.Nonce = common.GetInt64FromByte(b[31:39])
	vb, left, err := common.BytesWithLenToBytes(b[39:])
	if err != nil {
		return TxParam{}, []byte{}, fmt.Errorf("not enough bytes in TxParam unmarshaling (multisig hash tx)")
	}
	zeros := make([]byte, common.HashLength)
	if bytes.Equal(vb, zeros) {
		return tp, left, nil
	}
	copy(tp.MultiSignTx[:], vb)

	return tp, left, nil
}

func (tp TxParam) GetString() string {

	t := "Time: " + time.Unix(tp.SendingTime, 0).String() + "\n"
	t += "ChainID: " + strconv.Itoa(int(tp.ChainID)) + "\n"
	t += "Nonce: " + strconv.FormatInt(tp.Nonce, 10) + "\n"
	t += "Sender Address: " + tp.Sender.GetHex() + "\n"
	t += "Hash in multi sig transaction to confirm: " + tp.MultiSignTx.GetHex() + "\n"
	return t
}

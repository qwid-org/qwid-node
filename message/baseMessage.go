package message

import (
	"bytes"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// tx - transaction, gt - get transaction, st - sync transaction, "nn" - nonce, "bl" - block, "rb" - reject block, "hi" - GetHeight, "gh" - GetHeaders, "sh" - SendHeaders
var validHead = []string{"nn", "bl", "rb", "tx", "gt", "st", "bt", "hi", "gh", "sh", "bx"}

type BaseMessage struct {
	Head    []byte `json:"head"`
	ChainID int16  `json:"chainID"`
}

type AnyMessage interface {
	GetHead() []byte
	GetChainID() int16
	GetTransactionsBytes() map[[2]byte][][]byte
	GetBytes() []byte
	GetFromBytes([]byte) (AnyMessage, error)
}

func (m BaseMessage) GetBytes() []byte {
	b := m.Head[:]
	b = append(b, common.GetByteInt16(m.ChainID)...)
	return b
}

func (m *BaseMessage) GetFromBytes(b []byte) {
	if len(b) != 4 {
		logger.GetLogger().Println("bytes length should be 4")
		return
	}
	m.Head = b[:2]
	if !common.ContainsKey(validHead, string(m.Head)) {
		logger.GetLogger().Println("Head not in valid heads keys")
		return
	}
	m.ChainID = common.GetInt16FromByte(b[2:4])
	if m.ChainID != common.GetChainID() {
		logger.GetLogger().Println("Wrong Chain ID")
		return
	}
}

func CheckMessage(a AnyMessage) bool {
	isValidChainID := a.GetChainID() == common.GetChainID()

	isValidHead := false
	for _, key := range validHead {
		if bytes.Equal(a.GetHead(), []byte(key)) {
			isValidHead = true
			break
		}
	}
	return isValidHead && isValidChainID
}

func CheckValidMessage(m []byte) (bool, AnyMessage) {
	msg := TransactionsMessage{}
	amsg, err := msg.GetFromBytes(m)
	if err != nil {
		logger.GetLogger().Println(err)
		return false, msg
	}

	isValid := CheckMessage(amsg)
	if isValid == false {
		logger.GetLogger().Println("message is invalid")
		return false, msg
	}
	return true, amsg
}

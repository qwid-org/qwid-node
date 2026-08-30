package message

import (
	"sync"
	"time"
	"fmt"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/tcpip"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

var validTopics = [][2]byte{{'N', 'N'}, {'S', 'S'}, {'T', 'T'}, {'B', 'B'}}

type TransactionsMessage struct {
	BaseMessage       BaseMessage          `json:"base_message"`
	TransactionsBytes map[[2]byte][][]byte `json:"transactions_bytes"`
}

func (a TransactionsMessage) GetTransactionsBytes() map[[2]byte][][]byte {
	return a.TransactionsBytes
}

func (a TransactionsMessage) GetTransactionsFromBytes(sigName, sigName2 string, isPaused, isPaused2 bool) (map[[2]byte][]transactionsDefinition.Transaction, error) {
	txn := map[[2]byte][]transactionsDefinition.Transaction{}
	// One message can carry thousands of transactions, and a peer whose
	// transactions this node cannot accept re-gossips them every round. Counting
	// the rejects and logging one line per MESSAGE keeps that visible without
	// letting a single unhealthy peer own the log.
	var tooShort, failedVerify int
	var firstErr error
	for _, topic := range validTopics {
		if _, ok := a.TransactionsBytes[topic]; ok {
			for _, tb := range a.TransactionsBytes[topic] {
				tx := transactionsDefinition.Transaction{}
				at, rest, err := tx.GetFromBytes(tb)
				if err != nil || len(rest) > 0 {
					tooShort++
					if firstErr == nil {
						if err != nil {
							firstErr = err
						} else {
							firstErr = fmt.Errorf("%v trailing bytes after transaction", len(rest))
						}
					}
					continue
				}
				if topic == tcpip.NonceTopic || topic == tcpip.SelfNonceTopic {
					txn[topic] = append(txn[topic], at)
				} else if at.Verify(sigName, sigName2, isPaused, isPaused2) {
					txn[topic] = append(txn[topic], at)
				} else {
					failedVerify++
				}
			}
		}
	}
	if tooShort > 0 || failedVerify > 0 {
		// Throttled, and reporting the volume it suppressed. Anyone can send a
		// message full of transactions this node will refuse, so an untuned
		// line here is an amplifier: one forged transaction, one guaranteed
		// write. The decode error is named only when there was one — printing
		// "first decode error: <nil>" beside a purely unverifiable batch stated
		// a fact that did not exist.
		if ok, skipped := shouldLogDropSummary(); ok {
			detail := ""
			if tooShort > 0 {
				detail = fmt.Sprintf("; first decode error: %v", firstErr)
			}
			logger.GetLogger().Printf("warning: dropped %d undecodable and %d unverifiable transaction(s) from this message%s%s",
				tooShort, failedVerify, detail, dropSummarySuppressed(skipped))
		}
	}

	return txn, nil
}

func (b TransactionsMessage) GetHead() []byte {
	return b.BaseMessage.Head
}

func (b TransactionsMessage) GetChainID() int16 {
	return b.BaseMessage.ChainID
}

func (a TransactionsMessage) GetBytes() []byte {

	b := a.BaseMessage.GetBytes()
	b = append(b, common.GetByteInt32(int32(len(a.TransactionsBytes)))...)
	for key, sb := range a.TransactionsBytes {
		b = append(b, key[:]...)
		b = append(b, common.GetByteInt32(int32(len(sb)))...)
		for _, v := range sb {
			b = append(b, common.BytesToLenAndBytes(v)...)
		}
	}
	return b
}

func (a TransactionsMessage) GetFromBytes(b []byte) (AnyMessage, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("insufficient bytes for base message")
	}

	var err error
	a.BaseMessage.GetFromBytes(b[:4])
	if err != nil {
		return nil, err
	}

	b = b[4:]

	if len(b) < 4 {
		return nil, fmt.Errorf("insufficient bytes for transactions length")
	}

	n := common.GetInt32FromByte(b[:4])
	b = b[4:]

	a.TransactionsBytes = make(map[[2]byte][][]byte)

	for i := int32(0); i < n; i++ {
		if len(b) < 2 {
			return nil, fmt.Errorf("insufficient bytes for key")
		}
		var key [2]byte
		copy(key[:], b[:2])
		b = b[2:]

		if len(b) < 4 {
			return nil, fmt.Errorf("insufficient bytes for transactions size")
		}

		size := common.GetInt32FromByte(b[:4])
		b = b[4:]

		var sb []byte
		var transactions [][]byte
		for j := int32(0); j < size; j++ {
			if len(b) < 4 {
				return nil, fmt.Errorf("insufficient bytes for transaction length")
			}

			sb, b, err = common.BytesWithLenToBytes(b)
			if err != nil {
				logger.GetLogger().Println("unmarshal AnyNonceMessage from bytes fails")
				return nil, err
			}
			transactions = append(transactions, sb)
		}

		a.TransactionsBytes[key] = transactions
	}

	return AnyMessage(a), nil
}

// One report per interval for refused transactions, carrying how many messages
// were suppressed meanwhile. Global rather than per-peer: this decoder does not
// know which peer sent the message, and the point is to bound the total volume
// an attacker can force, not to attribute it.
var (
	dropLogMutex    sync.Mutex
	dropLogLast     time.Time
	dropLogSkipped  int
	dropLogInterval = 30 * time.Second
)

func shouldLogDropSummary() (bool, int) {
	now := time.Now()
	dropLogMutex.Lock()
	defer dropLogMutex.Unlock()
	if !dropLogLast.IsZero() && now.Sub(dropLogLast) < dropLogInterval {
		dropLogSkipped++
		return false, 0
	}
	dropLogLast = now
	n := dropLogSkipped
	dropLogSkipped = 0
	return true, n
}

func dropSummarySuppressed(skipped int) string {
	if skipped == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d further message(s) with refused transactions were suppressed)", skipped)
}

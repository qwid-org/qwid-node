package transactionServices

import (
	"bytes"
	"compress/flate"
	"io"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/tcpip"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// A bz envelope must round-trip: the inflated payload has to pass
// CheckValidMessage and come back as the exact bx message that went in —
// otherwise the receiver bans the sender for a malformed message.
func TestBzRoundTrip(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	sigBytes := make([]byte, 700)
	sigBytes[0] = 1
	sig, err := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	if err != nil {
		t.Fatalf("signature: %v", err)
	}
	txs := make([]transactionsDefinition.Transaction, 0, 20)
	for i := 0; i < 20; i++ {
		tx := transactionsDefinition.Transaction{
			TxParam:   transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: common.EmptyAddress(), Nonce: int64(i)},
			TxData:    transactionsDefinition.TxData{Recipient: common.EmptyAddress(), Amount: int64(i)},
			Height:    int64(i),
			Signature: sig,
		}
		if err := tx.CalcHashAndSet(); err != nil {
			t.Fatalf("hash: %v", err)
		}
		txs = append(txs, tx)
	}
	bxMsg, err := GenerateTransactionMsg(txs, []byte("bx"), tcpip.TransactionTopic)
	if err != nil {
		t.Fatalf("GenerateTransactionMsg: %v", err)
	}
	bxBytes := bxMsg.GetBytes()

	bzBytes, err := compressToBz(bxBytes, tcpip.TransactionTopic)
	if err != nil {
		t.Fatalf("compressToBz: %v", err)
	}
	ok, outer := message.CheckValidMessage(bzBytes)
	if !ok || string(outer.GetHead()) != "bz" {
		t.Fatal("bz envelope failed CheckValidMessage")
	}
	// Receiver side: inflate and validate, exactly as the bz case does.
	var inflated []byte
	for _, v := range outer.(message.TransactionsMessage).GetTransactionsBytes() {
		for _, zb := range v {
			fr := flate.NewReader(bytes.NewReader(zb))
			raw, err := io.ReadAll(io.LimitReader(fr, int64(common.MaxMessageSizeBytes)))
			fr.Close()
			if err != nil {
				t.Fatalf("inflate: %v", err)
			}
			inflated = raw
		}
	}
	if !bytes.Equal(inflated, bxBytes) {
		t.Fatalf("inflated payload differs from the original bx message (%d vs %d bytes)", len(inflated), len(bxBytes))
	}
	ok, inner := message.CheckValidMessage(inflated)
	if !ok || string(inner.GetHead()) != "bx" {
		t.Fatal("inflated payload is not a valid bx message")
	}
}

// QWID-2026-08: bz decompression must be bounded. A frame carrying more than
// one compressed item, or one that inflates past the bx policy cap, must be
// rejected — a single small frame must not force many/large decompressions.
func TestQWID08_BzDecompressionIsBounded(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	// A legitimate single-payload bz still inflates.
	sigBytes := make([]byte, 700)
	sigBytes[0] = 1
	sig, _ := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	tx := transactionsDefinition.Transaction{
		TxParam:   transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: common.EmptyAddress(), Nonce: 1},
		TxData:    transactionsDefinition.TxData{Recipient: common.EmptyAddress(), Amount: 1},
		Height:    1, Signature: sig,
	}
	_ = tx.CalcHashAndSet()
	bxMsg, _ := GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("bx"), tcpip.TransactionTopic)
	bzBytes, err := compressToBz(bxMsg.GetBytes(), tcpip.TransactionTopic)
	if err != nil {
		t.Fatalf("compressToBz: %v", err)
	}
	_, outer := message.CheckValidMessage(bzBytes)
	if _, err := validateAndInflateBz(outer.(message.TransactionsMessage).GetTransactionsBytes()); err != nil {
		t.Fatalf("a legitimate single-payload bz was rejected: %v", err)
	}

	// Two compressed items in one frame: rejected (the amplification vector).
	one := outer.(message.TransactionsMessage).GetTransactionsBytes()
	var zb []byte
	for _, v := range one {
		zb = v[0]
	}
	multi := map[[2]byte][][]byte{tcpip.TransactionTopic: {zb, zb}}
	if _, err := validateAndInflateBz(multi); err == nil {
		t.Fatal("a bz with two compressed items was accepted — one frame can force many decompressions (QWID-2026-08)")
	}

	// A payload that inflates past the cap: rejected, not truncated-and-accepted.
	var buf bytes.Buffer
	zw, _ := flate.NewWriter(&buf, flate.BestCompression)
	zeros := make([]byte, maxBzInflatedBytes+1024)
	_, _ = zw.Write(zeros)
	_ = zw.Close()
	bomb := map[[2]byte][][]byte{tcpip.TransactionTopic: {buf.Bytes()}}
	if _, err := validateAndInflateBz(bomb); err == nil {
		t.Fatal("a bz inflating past the cap was accepted — decompression-bomb guard is ineffective (QWID-2026-08)")
	}
}

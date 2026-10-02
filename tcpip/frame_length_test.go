package tcpip

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// S1-01: message bodies are raw binary and carry sender-chosen bytes
// (OptData, contract code). Framing must not depend on any byte sequence
// being absent from the body.
func TestFrameSurvivesDelimiterLikeBytesInBody(t *testing.T) {
	body := []byte("tx-data AA<-END->BB more<-CLS-> tail")
	fa := frameAssembler{topic: TransactionTopic}
	msgs, viol := fa.push(append(encodeFrame(body), encodeFrame([]byte("next"))...))
	if viol {
		t.Fatal("an honest frame must not be a violation")
	}
	if len(msgs) != 2 || !bytes.Equal(msgs[0], body) || string(msgs[1]) != "next" {
		t.Fatalf("msgs=%q", msgs)
	}
}

func TestEncodeFrameLayout(t *testing.T) {
	f := encodeFrame([]byte("abc"))
	if !bytes.Equal(f[:4], common.MessageInitialization[:]) {
		t.Fatal("frame must start with MessageInitialization")
	}
	if binary.BigEndian.Uint32(f[4:8]) != 3 || string(f[8:]) != "abc" {
		t.Fatalf("frame=%x", f)
	}
}

// A declared length over the topic cap is a violation, but the frame is
// skipped by count (never buffered), and the next frame parses normally.
func TestOverLongDeclaredLengthIsSkippedWithoutBuffering(t *testing.T) {
	topic := NonceTopic
	limit := MaxMessageSizeForTopic(topic)
	hdr := make([]byte, frameHeaderLen)
	copy(hdr, common.MessageInitialization[:])
	binary.BigEndian.PutUint32(hdr[4:], uint32(limit)+1)

	fa := frameAssembler{topic: topic}
	msgs, viol := fa.push(hdr)
	if !viol || len(msgs) != 0 {
		t.Fatalf("over-long header: msgs=%d viol=%v", len(msgs), viol)
	}
	chunk := make([]byte, 64*1024)
	for sent := 0; sent < int(limit)+1; sent += len(chunk) {
		n := min(len(chunk), int(limit)+1-sent)
		if msgs, viol = fa.push(chunk[:n]); viol || len(msgs) != 0 {
			t.Fatalf("skipped body: msgs=%d viol=%v", len(msgs), viol)
		}
		if cap(fa.buf) > 2*len(chunk) {
			t.Fatalf("skipped body is being buffered: cap=%d", cap(fa.buf))
		}
	}
	msgs, viol = fa.push(encodeFrame([]byte("after")))
	if viol || len(msgs) != 1 || string(msgs[0]) != "after" {
		t.Fatalf("frame after skipped one: msgs=%q viol=%v", msgs, viol)
	}
}

func TestEmptyBodyIsAViolation(t *testing.T) {
	fa := frameAssembler{topic: TransactionTopic}
	msgs, viol := fa.push(append(encodeFrame(nil), encodeFrame([]byte("ok"))...))
	if !viol || len(msgs) != 1 || string(msgs[0]) != "ok" {
		t.Fatalf("msgs=%q viol=%v", msgs, viol)
	}
}

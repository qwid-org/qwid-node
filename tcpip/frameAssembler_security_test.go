package tcpip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// QWID-01: an over-long frame must never be buffered. With length framing the
// declared size is known from the header, so its body is counted off.
func TestQWID01DiscardBufferIsBounded(t *testing.T) {
	fa := frameAssembler{} // Unknown topic uses the smallest production cap.
	limit := int(MaxMessageSizeForTopic(fa.topic))
	hdr := make([]byte, frameHeaderLen)
	copy(hdr, common.MessageInitialization[:])
	binary.BigEndian.PutUint32(hdr[4:], uint32(limit+16*1024*1024))
	msgs, violation := fa.push(hdr)
	if !violation || len(msgs) != 0 || fa.skip == 0 {
		t.Fatal("oversized frame must be skipped and reported as a violation")
	}
	chunk := bytes.Repeat([]byte{'x'}, 16*1024)
	for i := 0; fa.skip > 0; i++ {
		msgs, violation = fa.push(chunk)
		if violation || len(msgs) != 0 {
			t.Fatalf("discarded chunk %d changed framing state", i)
		}
		if cap(fa.buf) > len(chunk) {
			t.Fatalf("chunk %d retained cap=%d", i, cap(fa.buf))
		}
	}
	msgs, violation = fa.push(encodeFrame([]byte("recovered")))
	if len(msgs) != 1 || string(msgs[0]) != "recovered" {
		t.Fatalf("failed to recover: msgs=%q violation=%v", msgs, violation)
	}
}

// A frame exactly at the cap is legal however the stream is cut, including
// cuts inside the header.
func TestQWID01AcceptsLimitSizeFrameAtEverySplit(t *testing.T) {
	fa0 := frameAssembler{}
	body := bytes.Repeat([]byte{'x'}, int(MaxMessageSizeForTopic(fa0.topic)))
	wire := encodeFrame(body)
	for _, cut := range []int{1, 3, 4, 5, 7, 8, 9, len(wire) - 1} {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			fa := frameAssembler{}
			msgs, violation := fa.push(wire[:cut])
			if violation || len(msgs) != 0 {
				t.Fatal("partial frame reported early")
			}
			msgs, violation = fa.push(wire[cut:])
			if violation || len(msgs) != 1 || !bytes.Equal(msgs[0], body) {
				t.Fatal("legal frame at the cap was lost")
			}
		})
	}
}

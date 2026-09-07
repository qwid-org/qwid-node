package tcpip

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func securityTestFrame(payload []byte) []byte {
	wire := append([]byte(nil), common.MessageInitialization[:]...)
	wire = append(wire, payload...)
	return append(wire, frameEnd...)
}

func TestQWID01DiscardBufferIsBounded(t *testing.T) {
	fa := frameAssembler{} // Unknown topic uses the smallest production cap.
	limit := int(MaxMessageSizeForTopic(fa.topic))
	msgs, violation := fa.push(bytes.Repeat([]byte{'x'}, limit+1))
	if !violation || len(msgs) != 0 || !fa.discarding {
		t.Fatal("oversized frame must enter discard mode and report a violation")
	}
	chunk := bytes.Repeat([]byte{'x'}, 16*1024)
	for i := 0; i < 1024; i++ {
		msgs, violation = fa.push(chunk)
		if violation || len(msgs) != 0 || !fa.discarding {
			t.Fatalf("discarded chunk %d changed framing state", i)
		}
		// Check capacity too: a short subslice must not retain the huge buffer.
		if len(fa.buf) > len(frameEnd)-1 || cap(fa.buf) > len(frameEnd)-1 {
			t.Fatalf("chunk %d retained len=%d cap=%d; maximum is %d",
				i, len(fa.buf), cap(fa.buf), len(frameEnd)-1)
		}
	}
	msgs, violation = fa.push(append(append([]byte(nil), frameEnd...), securityTestFrame([]byte("recovered"))...))
	if violation || fa.discarding || len(msgs) != 1 || string(msgs[0]) != "recovered" {
		t.Fatalf("failed to recover: msgs=%q violation=%v", msgs, violation)
	}
}

func TestQWID01DiscardRecoversEveryDelimiterSplit(t *testing.T) {
	for split := 1; split < len(frameEnd); split++ {
		for _, entering := range []bool{true, false} {
			t.Run(fmt.Sprintf("split%d_entering%v", split, entering), func(t *testing.T) {
				fa := frameAssembler{}
				oversized := bytes.Repeat([]byte{'x'}, int(MaxMessageSizeForTopic(fa.topic))+1)
				if !entering {
					fa.push(oversized)
					oversized = []byte("more discarded bytes")
				}
				fa.push(append(oversized, frameEnd[:split]...))
				if !fa.discarding {
					t.Fatal("expected discard mode")
				}
				// Finish the discarded frame and start a valid frame in the same read.
				good := securityTestFrame([]byte("good"))
				msgs, violation := fa.push(append(append([]byte(nil), frameEnd[split:]...), good[:3]...))
				if violation || len(msgs) != 0 || fa.discarding {
					t.Fatal("split delimiter did not restore normal framing")
				}
				msgs, violation = fa.push(good[3:])
				if violation || len(msgs) != 1 || string(msgs[0]) != "good" {
					t.Fatalf("valid frame lost: msgs=%q violation=%v", msgs, violation)
				}
			})
		}
	}
}

func TestQWID01AcceptsLimitSizeFrameWithSplitDelimiter(t *testing.T) {
	for split := 0; split < len(frameEnd); split++ {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			fa := frameAssembler{}
			body := bytes.Repeat([]byte{'x'}, int(MaxMessageSizeForTopic(fa.topic))-len(common.MessageInitialization))
			wire := securityTestFrame(body)
			cut := len(wire) - len(frameEnd) + split
			msgs, violation := fa.push(wire[:cut])
			if violation || len(msgs) != 0 || fa.discarding {
				t.Fatal("partial delimiter counted against the legal frame size")
			}
			msgs, violation = fa.push(wire[cut:])
			if violation || len(msgs) != 1 || !bytes.Equal(msgs[0], body) {
				t.Fatal("legal frame at the cap was lost")
			}
		})
	}
}

package tcpip

import (
	"runtime"
	"testing"
)

// F-NET-01: assembling a frame must not copy everything buffered so far on
// every read. A 16 MB frame arriving in 16 KB records used to allocate ~8 GB.
func TestLargeFrameIsAssembledWithoutQuadraticCopying(t *testing.T) {
	const size = 16 << 20
	frame := encodeFrame(make([]byte, size))
	fa := frameAssembler{topic: TransactionTopic}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var got [][]byte
	for off := 0; off < len(frame); off += 16 * 1024 {
		end := min(off+16*1024, len(frame))
		p, viol := fa.push(frame[off:end])
		if viol {
			t.Fatal("violation")
		}
		got = append(got, p...)
	}
	runtime.ReadMemStats(&after)
	if len(got) != 1 || len(got[0]) != size {
		t.Fatalf("frames = %d", len(got))
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 256<<20 {
		t.Fatalf("assembling a %d MB frame allocated %d MB", size>>20, alloc>>20)
	}
}

// Payloads handed out stay intact while the assembler keeps reading.
func TestReturnedPayloadsSurviveLaterReads(t *testing.T) {
	a, b := encodeFrame([]byte("first-message")), encodeFrame([]byte("second-message!!"))
	fa := frameAssembler{topic: TransactionTopic}
	stream := append(append([]byte{}, a...), b...)
	p1, _ := fa.push(stream[:len(a)+5])
	if len(p1) != 1 {
		t.Fatalf("got %d payloads", len(p1))
	}
	p2, _ := fa.push(stream[len(a)+5:])
	for i := 0; i < 50; i++ {
		fa.push(encodeFrame([]byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")))
	}
	if string(p1[0]) != "first-message" || len(p2) != 1 || string(p2[0]) != "second-message!!" {
		t.Fatalf("payloads corrupted: %q %q", p1[0], p2)
	}
}

package tcpip

import (
	"net"
	"runtime"
	"testing"
)

func pipeWithKeys(t *testing.T) (*encryptedConn, net.Conn, net.Conn) {
	t.Helper()
	keys := &SessionKeys{WriteKey: make([]byte, 32), ReadKey: make([]byte, 32)}
	wRaw, rRaw := net.Pipe()
	t.Cleanup(func() { wRaw.Close(); rRaw.Close() })
	wc, _ := newEncryptedConn(wRaw, keys)
	rc, _ := newEncryptedConn(rRaw, keys)
	return wc.(*encryptedConn), wRaw, rc
}

func sendRecord(ec *encryptedConn, raw net.Conn, plaintext []byte) {
	ct := ec.writeAEAD.Seal(nil, recordNonce(ec.writeCtr), plaintext, nil)
	ec.writeCtr++
	raw.Write([]byte{0, 0, byte(len(ct) >> 8), byte(len(ct))})
	raw.Write(ct)
}

// S1-03: Write never emits an empty record, so one on the wire is abuse.
func TestEmptyRecordIsRejected(t *testing.T) {
	ec, raw, rc := pipeWithKeys(t)
	go sendRecord(ec, raw, nil)
	buf := make([]byte, 16)
	if _, err := rc.Read(buf); err == nil {
		t.Fatal("an empty record was accepted")
	}
}

// S1-03: receiving a tiny record must not cost a 64 KB allocation.
func TestReceiveAllocatesInProportionToData(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops items at random under -race; allocation is not measurable")
	}
	ec, raw, rc := pipeWithKeys(t)
	const n = 2000
	go func() {
		for i := 0; i < n; i++ {
			sendRecord(ec, raw, []byte{'x'})
		}
	}()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < n; i++ {
		if r := Receive(TransactionTopic, rc); len(r) != 1 {
			t.Fatalf("record %d: got %d bytes", i, len(r))
		}
	}
	runtime.ReadMemStats(&after)
	perRecord := (after.TotalAlloc - before.TotalAlloc) / n
	if perRecord > 1024 {
		t.Fatalf("receiving a 1-byte record allocates %d bytes", perRecord)
	}
}

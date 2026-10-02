package tcpip

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (r *recordingConn) Write(p []byte) (int, error) { return r.buf.Write(p) }

// S1-08: a read deadline that expires inside a record (header or ciphertext)
// must not lose the bytes already consumed; the next read resumes the record.
func TestReadResumesAfterTimeoutInsideRecord(t *testing.T) {
	keys := &SessionKeys{WriteKey: make([]byte, 32), ReadKey: make([]byte, 32)}
	for _, cut := range []int{2, 10} { // inside the header, inside the ciphertext
		wRaw, rRaw := net.Pipe()
		rc, _ := newEncryptedConn(rRaw, keys)
		rec := &recordingConn{}
		ec, _ := newEncryptedConn(rec, keys)
		ec.Write([]byte("hello-record"))
		first := len(rec.buf.Bytes())
		ec.Write([]byte("next"))
		wire := append([]byte(nil), rec.buf.Bytes()...)

		go func() {
			wRaw.Write(wire[:cut])
			time.Sleep(200 * time.Millisecond)
			wRaw.Write(wire[cut:first])
			wRaw.Write(wire[first:])
		}()
		rc.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
		buf := make([]byte, 64)
		if _, err := rc.Read(buf); err == nil {
			t.Fatalf("cut %d: expected a timeout", cut)
		} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("cut %d: expected a timeout, got %v", cut, err)
		}
		rc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := rc.Read(buf)
		if err != nil || string(buf[:n]) != "hello-record" {
			t.Fatalf("cut %d: after the timeout got %q, %v", cut, buf[:n], err)
		}
		n, err = rc.Read(buf)
		if err != nil || string(buf[:n]) != "next" {
			t.Fatalf("cut %d: following record got %q, %v", cut, buf[:n], err)
		}
		wRaw.Close()
		rRaw.Close()
	}
}

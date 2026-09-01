package tcpip

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func mirroredPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	a, b := net.Pipe()
	ea, err := newEncryptedConn(a, &SessionKeys{WriteKey: k1, ReadKey: k2})
	if err != nil {
		t.Fatal(err)
	}
	eb, err := newEncryptedConn(b, &SessionKeys{WriteKey: k2, ReadKey: k1}) // mirror
	if err != nil {
		t.Fatal(err)
	}
	return ea, eb
}

func TestEncryptedConnRoundTrip(t *testing.T) {
	ea, eb := mirroredPair(t)
	defer ea.Close()
	defer eb.Close()
	for _, size := range []int{0, 1, 100, 16 * 1024, 40 * 1024} { // incl. multi-record
		msg := make([]byte, size)
		rand.Read(msg)
		go func() { ea.Write(msg) }()
		got := make([]byte, size)
		if size > 0 {
			if _, err := io.ReadFull(eb, got); err != nil {
				t.Fatalf("size %d: %v", size, err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("size %d: round-trip mismatch", size)
			}
		}
	}
}

func TestEncryptedConnTamperDetected(t *testing.T) {
	// Wrap only the writer; read raw ciphertext, flip a byte, feed to a decrypting reader.
	k := make([]byte, 32)
	rand.Read(k)
	a, b := net.Pipe()
	ew, err := newEncryptedConn(a, &SessionKeys{WriteKey: k, ReadKey: k})
	if err != nil {
		t.Fatal(err)
	}
	er, err := newEncryptedConn(b, &SessionKeys{WriteKey: k, ReadKey: k})
	if err != nil {
		t.Fatal(err)
	}
	// Man-in-the-middle byte flip: write on a, corrupt in transit is hard over Pipe;
	// instead assert a corrupted record fails Open by writing a bad frame directly.
	go func() {
		defer a.Close()
		// valid-looking length + garbage body -> Open must fail
		a.Write([]byte{0x00, 0x00, 0x00, 0x20})
		a.Write(make([]byte, 0x20))
	}()
	buf := make([]byte, 16)
	if _, err := er.Read(buf); err == nil {
		t.Fatal("decrypt of garbage record must fail")
	}
	_ = ew
}

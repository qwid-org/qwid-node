package tcpip

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const maxRecordPayload = 16 * 1024

// SessionKeys are the two directional AEAD keys derived from the KEM handshake.
type SessionKeys struct {
	WriteKey []byte // 32 bytes — this side seals with it
	ReadKey  []byte // 32 bytes — this side opens with it
}

type encryptedConn struct {
	raw       net.Conn
	writeAEAD cipher.AEAD
	readAEAD  cipher.AEAD
	writeCtr  uint64
	readCtr   uint64
	writeMu   sync.Mutex
	readMu    sync.Mutex
	readBuf   []byte
}

func newEncryptedConn(raw net.Conn, keys *SessionKeys) (net.Conn, error) {
	wa, err := chacha20poly1305.New(keys.WriteKey)
	if err != nil {
		return nil, err
	}
	ra, err := chacha20poly1305.New(keys.ReadKey)
	if err != nil {
		return nil, err
	}
	return &encryptedConn{raw: raw, writeAEAD: wa, readAEAD: ra}, nil
}

func recordNonce(ctr uint64) []byte {
	var n [chacha20poly1305.NonceSize]byte // 12 bytes; first 4 zero, last 8 = counter
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n[:]
}

func (e *encryptedConn) Write(p []byte) (int, error) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxRecordPayload {
			chunk = chunk[:maxRecordPayload]
		}
		nonce := recordNonce(e.writeCtr)
		e.writeCtr++
		ct := e.writeAEAD.Seal(nil, nonce, chunk, nil)
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
		if _, err := e.raw.Write(hdr[:]); err != nil {
			return total, err
		}
		if _, err := e.raw.Write(ct); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (e *encryptedConn) Read(p []byte) (int, error) {
	e.readMu.Lock()
	defer e.readMu.Unlock()
	if len(e.readBuf) == 0 {
		var hdr [4]byte
		if _, err := io.ReadFull(e.raw, hdr[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint32(hdr[:]))
		if n < e.readAEAD.Overhead() || n > maxRecordPayload+e.readAEAD.Overhead() {
			return 0, fmt.Errorf("encryptedConn: bad record length %d", n)
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(e.raw, ct); err != nil {
			return 0, err
		}
		nonce := recordNonce(e.readCtr)
		e.readCtr++
		pt, err := e.readAEAD.Open(nil, nonce, ct, nil)
		if err != nil {
			return 0, fmt.Errorf("encryptedConn: decrypt failed: %w", err)
		}
		e.readBuf = pt
	}
	n := copy(p, e.readBuf)
	e.readBuf = e.readBuf[n:]
	return n, nil
}

func (e *encryptedConn) Close() error                       { return e.raw.Close() }
func (e *encryptedConn) LocalAddr() net.Addr                { return e.raw.LocalAddr() }
func (e *encryptedConn) RemoteAddr() net.Addr               { return e.raw.RemoteAddr() }
func (e *encryptedConn) SetDeadline(t time.Time) error      { return e.raw.SetDeadline(t) }
func (e *encryptedConn) SetReadDeadline(t time.Time) error  { return e.raw.SetReadDeadline(t) }
func (e *encryptedConn) SetWriteDeadline(t time.Time) error { return e.raw.SetWriteDeadline(t) }

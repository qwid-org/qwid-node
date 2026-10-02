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
	// Partial record state (S1-08). A read deadline can expire inside a
	// record; the bytes consumed so far are kept so the next Read resumes the
	// record instead of mistaking the middle of a ciphertext for a header.
	hdr  [4]byte
	hdrN int
	ct   []byte
	ctN  int
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
		for e.ct == nil {
			if err := readMore(e.raw, e.hdr[:], &e.hdrN); err != nil {
				return 0, err
			}
			n := int(binary.BigEndian.Uint32(e.hdr[:]))
			e.hdrN = 0
			// n == Overhead is an empty record. Write never sends one, and each
			// cost the reader a full receive cycle for 20 wire bytes (S1-03).
			if n <= e.readAEAD.Overhead() || n > maxRecordPayload+e.readAEAD.Overhead() {
				return 0, fmt.Errorf("encryptedConn: bad record length %d", n)
			}
			e.ct, e.ctN = make([]byte, n), 0
		}
		if err := readMore(e.raw, e.ct, &e.ctN); err != nil {
			return 0, err
		}
		ct := e.ct
		e.ct = nil
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

// readMore fills buf[*done:] from r, advancing *done as bytes arrive, so a
// timeout or other error leaves the progress in place for the next call.
func readMore(r io.Reader, buf []byte, done *int) error {
	for *done < len(buf) {
		n, err := r.Read(buf[*done:])
		*done += n
		if err != nil {
			if *done == len(buf) && err == io.EOF {
				return nil
			}
			if err == io.EOF && *done > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

func (e *encryptedConn) Close() error                       { return e.raw.Close() }
func (e *encryptedConn) LocalAddr() net.Addr                { return e.raw.LocalAddr() }
func (e *encryptedConn) RemoteAddr() net.Addr               { return e.raw.RemoteAddr() }
func (e *encryptedConn) SetDeadline(t time.Time) error      { return e.raw.SetDeadline(t) }
func (e *encryptedConn) SetReadDeadline(t time.Time) error  { return e.raw.SetReadDeadline(t) }
func (e *encryptedConn) SetWriteDeadline(t time.Time) error { return e.raw.SetWriteDeadline(t) }

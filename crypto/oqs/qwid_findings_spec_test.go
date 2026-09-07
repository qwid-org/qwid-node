package oqs

// Lock-in tests for the scheme-name parsing remediations (QWID-2026-32/33).
// These fixes are already applied; the tests must stay green so a later change
// cannot silently reopen the holes. See SECURITY_AUDIT_2026-09-05.md.

import (
	"encoding/binary"
	"testing"
)

// buildConfigBytes lays out a config field exactly as the wire format expects,
// but lets the caller inject an arbitrary 20-byte name field (the serializer
// GenerateBytesFromParams would reject a malformed name, which is the point).
func buildConfigBytes(name20 []byte, pub, priv, sig int32, paused bool) []byte {
	b := make([]byte, 0, totalLength)
	nb := make([]byte, sigNameLength)
	copy(nb, name20)
	b = append(b, nb...)
	for _, v := range []int32{pub, priv, sig} {
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(v))
		b = append(b, tmp...)
	}
	pb := byte(0)
	if paused {
		pb = 1
	}
	b = append(b, pb)
	return b
}

// QWID-2026-32: a name with data after an interior NUL aliases a real liboqs
// algorithm (C truncates at the NUL) while being a distinct Go string, slipping
// past every Go-side scheme-equality guard. The parser must reject it.
func TestQWID32_InteriorNulSchemeNameRejected(t *testing.T) {
	name := append([]byte("Falcon-padded-512"), 0x00, 'X') // 19 bytes, interior NUL then data
	bb := buildConfigBytes(name, 897, 1281, 666, false)
	if _, _, _, _, _, err := GenerateParamsEncryptionSchemesFromBytes(bb); err == nil {
		t.Fatal("a scheme name with bytes after an interior NUL was accepted — it aliases a real " +
			"algorithm past the duplicate-scheme and pause guards (QWID-2026-32)")
	}
}

// A legitimately NUL-padded name (the only valid encoding) must still parse.
func TestQWID32_TrailingNulPaddingStillAccepted(t *testing.T) {
	name := []byte("MAYO-2") // 6 bytes, rest is zero padding
	bb := buildConfigBytes(name, 4912, 24, 186, false)
	got, _, _, _, _, err := GenerateParamsEncryptionSchemesFromBytes(bb)
	if err != nil {
		t.Fatalf("a validly NUL-padded name failed to parse: %v", err)
	}
	if got != "MAYO-2" {
		t.Fatalf("name parsed as %q, want MAYO-2", got)
	}
}

// QWID-2026-33: an all-NUL (empty) name must be an explicit error, never a
// silent success that lets a nameless zero-length scheme be installed as live
// on the sync path.
func TestQWID33_EmptySchemeNameIsError(t *testing.T) {
	bb := buildConfigBytes(make([]byte, sigNameLength), 0, 0, 0, false)
	if _, err := FromBytesToEncryptionConfig(bb); err == nil {
		t.Fatal("an empty scheme name parsed as success — a nameless zero-length scheme could be " +
			"installed as the live scheme on a syncing node (QWID-2026-33)")
	}
}

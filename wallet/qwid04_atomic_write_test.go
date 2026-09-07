package wallet

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestQWID04_AtomicWriteFileReplacesCompletely verifies the QWID-2026-04 atomic
// write: the destination ends up with exactly the new content and owner-only
// (0600) permissions, and no temp file is left behind.
func TestQWID04_AtomicWriteFileReplacesCompletely(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet0.json")

	first := []byte(`{"v":1,"payload":"first"}`)
	if err := atomicWriteFile(path, first, 0600); err != nil {
		t.Fatalf("first atomicWriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after first write: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("first content mismatch: got %q want %q", got, first)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("new file perm = %o, want 0600", perm)
	}

	// Overwrite with different-length content; the result must be the complete
	// new document, never a splice of old and new bytes.
	second := []byte(`{"v":2,"payload":"a much longer replacement document than the first"}`)
	if err := atomicWriteFile(path, second, 0600); err != nil {
		t.Fatalf("second atomicWriteFile: %v", err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after second write: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("second content mismatch: got %q want %q", got, second)
	}

	// No temp files may linger in the directory — only the destination remains.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "wallet0.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory should hold only wallet0.json, got %v", names)
	}
}

// TestQWID04_AtomicWriteFileRepairsLegacyPermissions verifies that a
// pre-existing world-readable (0644) wallet is repaired to owner-only (0600) on
// the next save, closing the QWID-2026-04 legacy-permission exposure.
func TestQWID04_AtomicWriteFileRepairsLegacyPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet0.json")

	// Simulate a legacy wallet written before 0600 hardening.
	if err := os.WriteFile(path, []byte("legacy"), 0644); err != nil {
		t.Fatalf("seed legacy file: %v", err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0644 {
		t.Skipf("umask prevented seeding a 0644 file (got %o); skipping", fi.Mode().Perm())
	}

	if err := atomicWriteFile(path, []byte("hardened"), 0600); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("legacy perm not repaired: got %o, want 0600", perm)
	}
}

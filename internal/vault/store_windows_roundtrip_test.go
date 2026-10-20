//go:build windows

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadRoundTripOnACLFilesystem(t *testing.T) {
	root := os.Getenv("WARDKEY_TEST_NTFS_PATH")
	if root == "" {
		t.Skip("set WARDKEY_TEST_NTFS_PATH to a dedicated directory on an ACL-capable filesystem")
	}

	if err := CheckStorageFilesystem(root); err != nil {
		t.Fatalf("CheckStorageFilesystem(%q): %v", root, err)
	}

	temp, err := os.CreateTemp(root, "wardkey-test-*.wkv")
	if err != nil {
		t.Fatalf("create temporary test path: %v", err)
	}
	path := temp.Name()
	if err := temp.Close(); err != nil {
		t.Fatalf("close temporary test path: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("prepare new vault path: %v", err)
	}
	defer os.Remove(path)

	passphrase := []byte("wardkey dummy test passphrase")
	if err := Create(path, []Entry{}, passphrase); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := Create(path, []Entry{}, passphrase); !errors.Is(err, ErrVaultAlreadyExists) {
		t.Fatalf("second Create error = %v, want %v", err, ErrVaultAlreadyExists)
	}

	entries, err := Load(path, passphrase)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("Load returned %d entries, want 0", len(entries))
	}

	if err := Save(path, []Entry{}, passphrase); err != nil {
		t.Fatalf("replace existing vault: %v", err)
	}
	if _, err := Load(path, passphrase); err != nil {
		t.Fatalf("Load after replacement: %v", err)
	}

	wrongPassphrase := []byte("wardkey wrong test passphrase")
	if _, err := Load(path, wrongPassphrase); err == nil {
		t.Fatal("Load accepted an incorrect passphrase")
	}

	tampered, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read test vault for tampering: %v", err)
	}
	tampered[len(tampered)-1] ^= 0x01
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatalf("tamper with test vault: %v", err)
	}
	if _, err := Load(path, passphrase); err == nil {
		t.Fatal("Load accepted a tampered vault")
	}

	if filepath.Dir(path) != root {
		t.Fatalf("test vault escaped its dedicated directory: %q", path)
	}
}

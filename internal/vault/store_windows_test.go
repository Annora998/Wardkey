package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadRejectFilesystemWithoutACLs(t *testing.T) {
	root := os.Getenv("WARDKEY_TEST_NO_ACL_PATH")
	if root == "" {
		t.Skip("set WARDKEY_TEST_NO_ACL_PATH to a path on a filesystem without persistent ACLs")
	}

	path := filepath.Join(root, "wardkey-acl-guard-test.wkv")
	if err := CheckStorageFilesystem(root); !errors.Is(err, ErrACLsRequired) {
		t.Fatalf("CheckStorageFilesystem error = %v, want %v", err, ErrACLsRequired)
	}

	if err := Save(path, nil, nil); !errors.Is(err, ErrACLsRequired) {
		t.Fatalf("Save error = %v, want %v", err, ErrACLsRequired)
	}
	if _, err := Load(path, nil); !errors.Is(err, ErrACLsRequired) {
		t.Fatalf("Load error = %v, want %v", err, ErrACLsRequired)
	}
}

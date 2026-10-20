package vault

import (
	"errors"
	"os"
	"testing"
)

func TestEnsurePrivateDirectoryRejectsFilesystemWithoutACLs(t *testing.T) {
	path := os.Getenv("WARDKEY_TEST_NO_ACL_PATH")
	if path == "" {
		t.Skip("set WARDKEY_TEST_NO_ACL_PATH to a path on a filesystem without persistent ACLs")
	}

	err := ensurePrivateDirectory(path)
	if !errors.Is(err, ErrACLsRequired) {
		t.Fatalf("ensurePrivateDirectory(%q) error = %v, want %v", path, err, ErrACLsRequired)
	}
}

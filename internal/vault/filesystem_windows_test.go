package vault

import (
	"errors"
	"os"
	"testing"
)

func TestConfiguredFAT32PathIsRejected(t *testing.T) {
	path := os.Getenv("WARDKEY_TEST_NO_ACL_PATH")
	if path == "" {
		t.Skip("set WARDKEY_TEST_NO_ACL_PATH to a path on a filesystem without persistent ACLs")
	}

	err := requireACLFilesystem(path)
	if !errors.Is(err, ErrACLsRequired) {
		t.Fatalf("requireACLFilesystem(%q) error = %v, want ErrACLsRequired", path, err)
	}
}

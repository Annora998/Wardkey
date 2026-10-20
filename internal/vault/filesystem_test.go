package vault

import (
	"errors"
	"testing"
)

func TestCheckACLFlags(t *testing.T) {
	if err := checkACLFlags(0); !errors.Is(err, ErrACLsRequired) {
		t.Fatalf("checkACLFlags(0) error = %v, want ErrACLsRequired", err)
	}

	if err := checkACLFlags(persistentACLsFlag); err != nil {
		t.Fatalf("checkACLFlags(persistentACLsFlag) error = %v, want nil", err)
	}

	if err := checkACLFlags(persistentACLsFlag | 0x1); err != nil {
		t.Fatalf("checkACLFlags(with extra flags) error = %v, want nil", err)
	}
}

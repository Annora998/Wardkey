package broker

import (
	"testing"

	"wardkey/internal/vault"
)

func TestSessionIsDecoyUsesExactMatchWithoutExposingValue(t *testing.T) {
	session := NewSession()

	decoy, err := vault.NewDecoyEntry("aws", "decoy-profile", []byte("dummy decoy value"))
	if err != nil {
		t.Fatalf("NewDecoyEntry() error = %v", err)
	}
	ordinary, err := vault.NewEntry("generic", "ordinary-profile", []byte("dummy ordinary value"))
	if err != nil {
		t.Fatalf("NewEntry() error = %v", err)
	}

	if err := session.Unlock([]vault.Entry{decoy, ordinary}); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
	defer session.Close()

	tests := []struct {
		provider string
		name     string
		want     bool
	}{
		{provider: "aws", name: "decoy-profile", want: true},
		{provider: "generic", name: "ordinary-profile", want: false},
		{provider: "aws", name: "other-profile", want: false},
	}

	for _, test := range tests {
		got, err := session.IsDecoy(test.provider, test.name)
		if err != nil {
			t.Errorf("IsDecoy(%q, %q) error = %v", test.provider, test.name, err)
			continue
		}
		if got != test.want {
			t.Errorf("IsDecoy(%q, %q) = %t, want %t",
				test.provider, test.name, got, test.want)
		}
	}
}

func TestSessionIsDecoyRejectsLockedSession(t *testing.T) {
	session := NewSession()

	if _, err := session.IsDecoy("aws", "decoy-profile"); err != ErrSessionLocked {
		t.Fatalf("IsDecoy() error = %v, want ErrSessionLocked", err)
	}
}

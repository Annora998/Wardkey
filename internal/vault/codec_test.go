package vault

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptAndDecryptEntries(t *testing.T) {
	want := []Entry{
		newTestEntry(t, "aws", "dev", "dummy AWS test value"),
		newTestEntry(t, "generic", "example", "dummy generic test value"),
	}
	defer zeroEntries(want)

	blob, err := EncryptEntries([]byte("dummy test passphrase"), want)
	if err != nil {
		t.Fatalf("EncryptEntries() error = %v", err)
	}
	defer zero(blob)

	got, err := DecryptEntries([]byte("dummy test passphrase"), blob)
	if err != nil {
		t.Fatalf("DecryptEntries() error = %v", err)
	}
	defer zeroEntries(got)

	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID ||
			got[i].Provider != want[i].Provider ||
			got[i].Name != want[i].Name ||
			!bytes.Equal(got[i].Value, want[i].Value) {
			t.Errorf("entry %d did not round-trip", i)
		}
	}
}

func TestDecryptEntriesRejectsWrongPassphrase(t *testing.T) {
	entry := newTestEntry(t, "generic", "example", "dummy test value")
	defer zeroEntries([]Entry{entry})

	blob, err := EncryptEntries([]byte("dummy correct passphrase"), []Entry{entry})
	if err != nil {
		t.Fatalf("EncryptEntries() error = %v", err)
	}
	defer zero(blob)

	_, err = DecryptEntries([]byte("dummy incorrect passphrase"), blob)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("DecryptEntries() error = %v, want ErrAuthentication", err)
	}
}

func TestEncryptEntriesRejectsInvalidEntries(t *testing.T) {
	entry := newTestEntry(t, "generic", "example", "dummy test value")
	defer zeroEntries([]Entry{entry})
	entry.Provider = "unknown"

	if _, err := EncryptEntries([]byte("dummy test passphrase"), []Entry{entry}); err == nil {
		t.Fatal("EncryptEntries() error = nil, want invalid entry error")
	}
}

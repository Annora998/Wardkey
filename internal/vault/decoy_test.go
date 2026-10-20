package vault

import (
	"bytes"
	"testing"
)

func TestNewDecoyEntryRoundTripsMarker(t *testing.T) {
	input := []byte("dummy decoy value")
	entry, err := NewDecoyEntry("generic", "decoy-test", input)
	if err != nil {
		t.Fatalf("NewDecoyEntry() error = %v", err)
	}
	defer zero(entry.Value)

	input[0] = 'X'
	if string(entry.Value) != "dummy decoy value" {
		t.Fatal("decoy entry did not copy the input value")
	}
	if !entry.Decoy {
		t.Fatal("NewDecoyEntry() did not mark the entry as a decoy")
	}

	data, err := MarshalEntries([]Entry{entry})
	if err != nil {
		t.Fatalf("MarshalEntries() error = %v", err)
	}
	defer zero(data)

	got, err := UnmarshalEntries(data)
	if err != nil {
		t.Fatalf("UnmarshalEntries() error = %v", err)
	}
	defer zeroEntries(got)

	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if !got[0].Decoy {
		t.Fatal("decoy marker was not preserved")
	}
	if !bytes.Equal(got[0].Value, entry.Value) {
		t.Fatal("decoy value did not round-trip")
	}
}

func TestNewEntryIsNotDecoy(t *testing.T) {
	entry, err := NewEntry("generic", "ordinary-test", []byte("dummy ordinary value"))
	if err != nil {
		t.Fatalf("NewEntry() error = %v", err)
	}
	defer zero(entry.Value)

	if entry.Decoy {
		t.Fatal("NewEntry() unexpectedly marked an ordinary entry as a decoy")
	}
}

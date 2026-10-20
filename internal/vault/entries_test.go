package vault

import (
	"bytes"
	"testing"
)

func newTestEntry(t *testing.T, provider, name, value string) Entry {
	t.Helper()

	entry, err := NewEntry(provider, name, []byte(value))
	if err != nil {
		t.Fatalf("NewEntry() error = %v", err)
	}
	return entry
}

func TestNewEntryCopiesValue(t *testing.T) {
	input := []byte("dummy test secret")
	entry, err := NewEntry("generic", "example", input)
	if err != nil {
		t.Fatalf("NewEntry() error = %v", err)
	}

	input[0] = 'X'
	if bytes.Equal(entry.Value, input) {
		t.Fatal("entry value unexpectedly shares the caller's input buffer")
	}
	if string(entry.Value) != "dummy test secret" {
		t.Fatalf("entry value changed unexpectedly: %q", entry.Value)
	}
}

func TestMarshalAndUnmarshalEntries(t *testing.T) {
	want := []Entry{
		newTestEntry(t, "aws", "dev", "dummy AWS test value"),
		newTestEntry(t, "github", "work", "dummy GitHub test value"),
	}

	data, err := MarshalEntries(want)
	if err != nil {
		t.Fatalf("MarshalEntries() error = %v", err)
	}
	defer zero(data)

	got, err := UnmarshalEntries(data)
	if err != nil {
		t.Fatalf("UnmarshalEntries() error = %v", err)
	}
	defer zeroEntries(got)

	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID ||
			got[i].Provider != want[i].Provider ||
			got[i].Name != want[i].Name ||
			!bytes.Equal(got[i].Value, want[i].Value) ||
			!got[i].CreatedAt.Equal(want[i].CreatedAt) {
			t.Errorf("entry %d did not round-trip", i)
		}
	}
}

func TestMarshalEntriesRejectsDuplicateNames(t *testing.T) {
	first := newTestEntry(t, "aws", "dev", "dummy first value")
	second := newTestEntry(t, "aws", "dev", "dummy second value")

	if _, err := MarshalEntries([]Entry{first, second}); err == nil {
		t.Fatal("MarshalEntries() error = nil, want duplicate name error")
	}
}

func TestMarshalEntriesRejectsInvalidProvider(t *testing.T) {
	entry := newTestEntry(t, "generic", "example", "dummy test value")
	entry.Provider = "unknown"

	if _, err := MarshalEntries([]Entry{entry}); err == nil {
		t.Fatal("MarshalEntries() error = nil, want invalid provider error")
	}
}

func TestUnmarshalEntriesRejectsTrailingJSON(t *testing.T) {
	entry := newTestEntry(t, "generic", "example", "dummy test value")
	data, err := MarshalEntries([]Entry{entry})
	if err != nil {
		t.Fatalf("MarshalEntries() error = %v", err)
	}
	defer zero(data)

	data = append(data, []byte(` {}`)...)
	if _, err := UnmarshalEntries(data); err == nil {
		t.Fatal("UnmarshalEntries() error = nil, want trailing JSON error")
	}
}

func TestNewEntryRejectsEmptyValue(t *testing.T) {
	if _, err := NewEntry("generic", "example", nil); err == nil {
		t.Fatal("NewEntry() error = nil, want empty value error")
	}
}

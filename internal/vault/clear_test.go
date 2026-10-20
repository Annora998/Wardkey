package vault

import (
	"bytes"
	"testing"
)

func TestEntryClearZerosSecret(t *testing.T) {
	entry := newTestEntry(t, "generic", "example", "dummy test value")
	valueBuffer := entry.Value

	entry.Clear()

	if entry.Value != nil {
		t.Fatal("Entry.Clear() did not release the value slice")
	}
	if !bytes.Equal(valueBuffer, make([]byte, len(valueBuffer))) {
		t.Fatal("Entry.Clear() did not zero the original value buffer")
	}
}

func TestClearEntriesZerosSecrets(t *testing.T) {
	entries := []Entry{
		newTestEntry(t, "aws", "dev", "dummy AWS value"),
		newTestEntry(t, "github", "work", "dummy GitHub value"),
	}
	valueBuffers := [][]byte{entries[0].Value, entries[1].Value}

	ClearEntries(entries)

	for i, entry := range entries {
		if entry.Value != nil {
			t.Errorf("entry %d still has a value slice", i)
		}
		if !bytes.Equal(valueBuffers[i], make([]byte, len(valueBuffers[i]))) {
			t.Errorf("entry %d value buffer was not zeroed", i)
		}
	}
}

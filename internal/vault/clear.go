package vault

// Clear zeros an entry's secret bytes and releases its slice.
// Memory clearing in Go is best-effort; callers should keep secret lifetimes short.
func (entry *Entry) Clear() {
	if entry == nil {
		return
	}
	zero(entry.Value)
	entry.Value = nil
}

// ClearEntries clears the secret values in a collection of entries.
func ClearEntries(entries []Entry) {
	for i := range entries {
		entries[i].Clear()
	}
}

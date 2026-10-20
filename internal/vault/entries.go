package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxEntries         = 1024
	MaxEntryValueSize  = 1 << 20
	MaxPayloadSize     = 8 << 20
	payloadVersion     = 1
	maxEntryNameLength = 128
)

var ErrInvalidEntry = errors.New("invalid vault entry")

// Entry holds one credential. Decoy entries are bait: the broker must never
// pass their values to a credential executor. Callers must clear Value buffers.
type Entry struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Name      string    `json:"name"`
	Value     []byte    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	Decoy     bool      `json:"decoy,omitempty"`
}

type payload struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// NewEntry validates its inputs and makes a private copy of value.
func NewEntry(provider, name string, value []byte) (Entry, error) {
	return newEntry(provider, name, value, false)
}

// NewDecoyEntry creates an encrypted bait entry. Its value must never be
// released to Git, AWS CLI, or any other credential executor.
func NewDecoyEntry(provider, name string, value []byte) (Entry, error) {
	return newEntry(provider, name, value, true)
}

func newEntry(provider, name string, value []byte, decoy bool) (Entry, error) {
	if err := validateProviderAndName(provider, name); err != nil {
		return Entry{}, err
	}
	if len(value) == 0 || len(value) > MaxEntryValueSize {
		return Entry{}, ErrInvalidEntry
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return Entry{}, fmt.Errorf("generate entry ID: %w", err)
	}

	valueCopy := append([]byte(nil), value...)
	return Entry{
		ID:        hex.EncodeToString(idBytes),
		Provider:  provider,
		Name:      name,
		Value:     valueCopy,
		CreatedAt: time.Now().UTC(),
		Decoy:     decoy,
	}, nil
}

// MarshalEntries encodes entries as plaintext JSON for encryption.
// The caller must clear the returned buffer after sealing it.
func MarshalEntries(entries []Entry) ([]byte, error) {
	if err := validateEntries(entries); err != nil {
		return nil, err
	}

	data, err := json.Marshal(payload{Version: payloadVersion, Entries: entries})
	if err != nil {
		return nil, fmt.Errorf("encode vault entries: %w", err)
	}
	if len(data) > MaxPayloadSize {
		return nil, ErrVaultTooLarge
	}
	return data, nil
}

// UnmarshalEntries decodes and validates a plaintext vault payload.
func UnmarshalEntries(data []byte) ([]Entry, error) {
	if len(data) == 0 || len(data) > MaxPayloadSize {
		return nil, ErrInvalidVault
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var stored payload
	if err := decoder.Decode(&stored); err != nil {
		return nil, ErrInvalidVault
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		zeroEntries(stored.Entries)
		return nil, ErrInvalidVault
	}
	if stored.Version != payloadVersion {
		zeroEntries(stored.Entries)
		return nil, ErrInvalidVault
	}
	if err := validateEntries(stored.Entries); err != nil {
		zeroEntries(stored.Entries)
		return nil, err
	}

	return stored.Entries, nil
}

func validateEntries(entries []Entry) error {
	if len(entries) > MaxEntries {
		return ErrInvalidEntry
	}

	ids := make(map[string]struct{}, len(entries))
	names := make(map[string]struct{}, len(entries))

	for _, entry := range entries {
		if len(entry.ID) != 32 || strings.ToLower(entry.ID) != entry.ID {
			return ErrInvalidEntry
		}
		if _, err := hex.DecodeString(entry.ID); err != nil {
			return ErrInvalidEntry
		}
		if err := validateProviderAndName(entry.Provider, entry.Name); err != nil {
			return err
		}
		if len(entry.Value) == 0 || len(entry.Value) > MaxEntryValueSize || entry.CreatedAt.IsZero() {
			return ErrInvalidEntry
		}

		if _, exists := ids[entry.ID]; exists {
			return ErrInvalidEntry
		}
		ids[entry.ID] = struct{}{}

		nameKey := entry.Provider + "\x00" + entry.Name
		if _, exists := names[nameKey]; exists {
			return ErrInvalidEntry
		}
		names[nameKey] = struct{}{}
	}

	return nil
}

func validateProviderAndName(provider, name string) error {
	switch provider {
	case "aws", "github", "npm", "generic":
	default:
		return ErrInvalidEntry
	}

	if name == "" || len(name) > maxEntryNameLength || !utf8.ValidString(name) {
		return ErrInvalidEntry
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return ErrInvalidEntry
		}
	}
	return nil
}

func zeroEntries(entries []Entry) {
	for i := range entries {
		for j := range entries[i].Value {
			entries[i].Value[j] = 0
		}
	}
}

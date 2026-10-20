package vault

import (
	"errors"
	"fmt"
)

var ErrVaultAlreadyExists = errors.New("vault already exists")

// Create encrypts entries and refuses to overwrite an existing vault.
func Create(path string, entries []Entry, passphrase []byte) error {
	if err := requireACLFilesystem(path); err != nil {
		return fmt.Errorf("vault path: %w", err)
	}

	encryptedData, err := EncryptEntries(passphrase, entries)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	if err := createVaultAtomically(path, encryptedData); err != nil {
		return fmt.Errorf("create vault: %w", err)
	}

	return nil
}

// Save encrypts entries with a new data key. Use this to create a new v2
// encryption key, such as when migrating a legacy vault.
func Save(path string, entries []Entry, passphrase []byte) error {
	if err := requireACLFilesystem(path); err != nil {
		return fmt.Errorf("vault path: %w", err)
	}

	encryptedData, err := EncryptEntries(passphrase, entries)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	if err := writeVaultAtomically(path, encryptedData); err != nil {
		return fmt.Errorf("save vault: %w", err)
	}

	return nil
}

// SaveWithDataKey encrypts entries using the existing v2 data key, preserving
// keys derived from it, such as the audit-log key.
func SaveWithDataKey(
	path string,
	entries []Entry,
	passphrase []byte,
	dataKey []byte,
) error {
	if err := requireACLFilesystem(path); err != nil {
		return fmt.Errorf("vault path: %w", err)
	}

	encryptedData, err := EncryptEntriesWithDataKey(passphrase, entries, dataKey)
	if err != nil {
		return fmt.Errorf("encrypt vault with existing data key: %w", err)
	}

	if err := writeVaultAtomically(path, encryptedData); err != nil {
		return fmt.Errorf("save vault: %w", err)
	}

	return nil
}

// Load reads and decrypts entries from a private vault path.
func Load(path string, passphrase []byte) ([]Entry, error) {
	if err := requireACLFilesystem(path); err != nil {
		return nil, fmt.Errorf("vault path: %w", err)
	}

	encryptedData, err := readVaultFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vault: %w", err)
	}

	entries, err := DecryptEntries(passphrase, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault: %w", err)
	}

	return entries, nil
}

// LoadWithDataKey reads a version 2 vault and returns its decrypted entries
// and random data key. The caller owns both results and must clear them.
// Version 1 vaults return ErrDataKeyUnavailable.
func LoadWithDataKey(path string, passphrase []byte) ([]Entry, []byte, error) {
	if err := requireACLFilesystem(path); err != nil {
		return nil, nil, fmt.Errorf("vault path: %w", err)
	}

	encryptedData, err := readVaultFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read vault: %w", err)
	}

	entries, dataKey, err := DecryptEntriesWithDataKey(passphrase, encryptedData)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt vault with data key: %w", err)
	}

	return entries, dataKey, nil
}

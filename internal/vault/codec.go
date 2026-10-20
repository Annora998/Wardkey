package vault

// EncryptEntries validates and encrypts entries with a new data key. It clears
// the temporary plaintext JSON buffer before returning.
func EncryptEntries(passphrase []byte, entries []Entry) ([]byte, error) {
	plaintext, err := MarshalEntries(entries)
	if err != nil {
		return nil, err
	}
	defer zero(plaintext)

	return Seal(passphrase, plaintext)
}

// EncryptEntriesWithDataKey validates and encrypts entries using the existing
// data key. It clears the temporary plaintext JSON buffer before returning.
// The caller remains responsible for clearing dataKey.
func EncryptEntriesWithDataKey(
	passphrase []byte,
	entries []Entry,
	dataKey []byte,
) ([]byte, error) {
	plaintext, err := MarshalEntries(entries)
	if err != nil {
		return nil, err
	}
	defer zero(plaintext)

	return SealWithDataKey(passphrase, plaintext, dataKey)
}

// DecryptEntries authenticates, decrypts, and validates a vault payload.
// The returned entries contain secret bytes that the caller must clear.
func DecryptEntries(passphrase, blob []byte) ([]Entry, error) {
	plaintext, err := Open(passphrase, blob)
	if err != nil {
		return nil, err
	}
	defer zero(plaintext)

	return UnmarshalEntries(plaintext)
}

// DecryptEntriesWithDataKey authenticates, decrypts, and validates a version 2
// vault payload. The caller owns the returned entries and data key and must
// clear both when finished. Version 1 vaults return ErrDataKeyUnavailable.
func DecryptEntriesWithDataKey(passphrase, blob []byte) ([]Entry, []byte, error) {
	plaintext, dataKey, err := OpenWithDataKey(passphrase, blob)
	if err != nil {
		return nil, nil, err
	}
	defer zero(plaintext)

	entries, err := UnmarshalEntries(plaintext)
	if err != nil {
		zero(dataKey)
		return nil, nil, err
	}

	return entries, dataKey, nil
}

package vault

import "fmt"

// LoadWithAuditKey loads a version 2 vault and returns its entries plus a
// dedicated audit key. The caller owns the returned entries and audit key
// and must clear them when finished.
func LoadWithAuditKey(path string, passphrase []byte) ([]Entry, []byte, error) {
	entries, auditKey, approvalKey, err := LoadWithSessionKeys(path, passphrase)
	if err != nil {
		return nil, nil, err
	}
	zero(approvalKey)

	return entries, auditKey, nil
}

// LoadWithSessionKeys loads a version 2 vault and derives separate audit and
// approval keys from its stable data key. The caller owns all returned values
// and must clear them when finished.
func LoadWithSessionKeys(path string, passphrase []byte) ([]Entry, []byte, []byte, error) {
	entries, dataKey, err := LoadWithDataKey(path, passphrase)
	if err != nil {
		return nil, nil, nil, err
	}
	defer zero(dataKey)

	auditKey, err := DeriveAuditKey(dataKey)
	if err != nil {
		clearAuditKeyLoadedEntries(entries)
		return nil, nil, nil, fmt.Errorf("derive audit key: %w", err)
	}

	approvalKey, err := DeriveApprovalKey(dataKey)
	if err != nil {
		clearAuditKeyLoadedEntries(entries)
		zero(auditKey)
		return nil, nil, nil, fmt.Errorf("derive approval key: %w", err)
	}

	return entries, auditKey, approvalKey, nil
}

func clearAuditKeyLoadedEntries(entries []Entry) {
	for i := range entries {
		clear(entries[i].Value)
		entries[i] = Entry{}
	}
}

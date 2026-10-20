package vault

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	AuditKeySize    = 32
	ApprovalKeySize = 32
)

var ErrInvalidDataKey = errors.New("invalid vault data key")

// DeriveAuditKey derives a dedicated HMAC key from a version 2 vault data key.
// The returned key is owned by the caller and must be cleared when finished.
func DeriveAuditKey(dataKey []byte) ([]byte, error) {
	return deriveVaultKey(dataKey, AuditKeySize, "wardkey/audit-log/hmac-sha256/v1")
}

// DeriveApprovalKey derives a separate key for authenticating approval
// enrollment metadata. The returned key is owned by the caller and must be
// cleared when finished.
func DeriveApprovalKey(dataKey []byte) ([]byte, error) {
	return deriveVaultKey(dataKey, ApprovalKeySize, "wardkey/approval-record/hmac-sha256/v1")
}

func deriveVaultKey(dataKey []byte, size int, info string) ([]byte, error) {
	if len(dataKey) != chacha20poly1305.KeySize {
		return nil, ErrInvalidDataKey
	}

	reader := hkdf.New(sha256.New, dataKey, nil, []byte(info))
	key := make([]byte, size)
	if _, err := io.ReadFull(reader, key); err != nil {
		zero(key)
		return nil, fmt.Errorf("derive vault key: %w", err)
	}

	return key, nil
}

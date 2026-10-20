package vault

import (
	"bytes"
	"errors"
	"testing"
)

func TestDeriveAuditKeyIsDeterministicAndSeparated(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x42}, AuditKeySize)
	otherDataKey := bytes.Repeat([]byte{0x43}, AuditKeySize)

	first, err := DeriveAuditKey(dataKey)
	if err != nil {
		t.Fatalf("DeriveAuditKey() error = %v", err)
	}
	defer zero(first)

	second, err := DeriveAuditKey(dataKey)
	if err != nil {
		t.Fatalf("DeriveAuditKey() second call error = %v", err)
	}
	defer zero(second)

	other, err := DeriveAuditKey(otherDataKey)
	if err != nil {
		t.Fatalf("DeriveAuditKey() with different key error = %v", err)
	}
	defer zero(other)

	if len(first) != AuditKeySize {
		t.Fatalf("derived key length = %d, want %d", len(first), AuditKeySize)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("same data key produced different audit keys")
	}
	if bytes.Equal(first, other) {
		t.Fatal("different data keys produced the same audit key")
	}
}

func TestDeriveAuditKeyRejectsInvalidKeyLength(t *testing.T) {
	_, err := DeriveAuditKey(make([]byte, AuditKeySize-1))
	if !errors.Is(err, ErrInvalidDataKey) {
		t.Fatalf("DeriveAuditKey() error = %v, want ErrInvalidDataKey", err)
	}
}

//go:build windows

package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"wardkey/internal/vault"
)

func TestLoggerAppendAndVerifyOnACLFilesystem(t *testing.T) {
	testDirectory := newAuditTestDirectory(t)
	logPath := filepath.Join(testDirectory, "audit.jsonl")
	key := bytes.Repeat([]byte{0x51}, vault.AuditKeySize)

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}
	if err := logger.Verify(key); err != nil {
		t.Fatalf("Verify() on empty log error = %v", err)
	}

	event := Event{
		Type:     "credential.request",
		Outcome:  "denied",
		Provider: "generic",
		Profile:  "demo",
	}
	if err := logger.Append(key, event); err != nil {
		t.Fatalf("Append(first) error = %v", err)
	}
	if err := logger.Append(key, Event{
		Type:    "vault.lock",
		Outcome: "success",
	}); err != nil {
		t.Fatalf("Append(second) error = %v", err)
	}

	if err := logger.Verify(key); err != nil {
		t.Fatalf("Verify() after appends error = %v", err)
	}
}

func TestLoggerDetectsTamperedRecord(t *testing.T) {
	testDirectory := newAuditTestDirectory(t)
	logPath := filepath.Join(testDirectory, "audit.jsonl")
	key := bytes.Repeat([]byte{0x52}, vault.AuditKeySize)

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}
	if err := logger.Append(key, Event{
		Type:    "credential.request",
		Outcome: "denied",
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	tampered := bytes.Replace(
		data,
		[]byte(`"outcome":"denied"`),
		[]byte(`"outcome":"allowed"`),
		1,
	)
	if bytes.Equal(data, tampered) {
		t.Fatal("test could not find the event outcome to tamper with")
	}
	if err := os.WriteFile(logPath, tampered, 0600); err != nil {
		t.Fatalf("WriteFile() tampering error = %v", err)
	}

	if err := logger.Verify(key); !errors.Is(err, ErrLogIntegrity) {
		t.Fatalf("Verify() error = %v, want ErrLogIntegrity", err)
	}
	if err := logger.Append(key, Event{
		Type:    "vault.lock",
		Outcome: "success",
	}); !errors.Is(err, ErrLogIntegrity) {
		t.Fatalf("Append() after tampering error = %v, want ErrLogIntegrity", err)
	}
}

func TestLoggerDetectsIncompleteFinalRecord(t *testing.T) {
	testDirectory := newAuditTestDirectory(t)
	logPath := filepath.Join(testDirectory, "audit.jsonl")
	key := bytes.Repeat([]byte{0x53}, vault.AuditKeySize)

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}
	if err := logger.Append(key, Event{
		Type:    "vault.unlock",
		Outcome: "success",
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	if _, err := file.Write([]byte(`{"partial":`)); err != nil {
		file.Close()
		t.Fatalf("write incomplete record: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if err := logger.Verify(key); !errors.Is(err, ErrLogIntegrity) {
		t.Fatalf("Verify() error = %v, want ErrLogIntegrity", err)
	}
}

func newAuditTestDirectory(t *testing.T) string {
	t.Helper()

	root := os.Getenv("WARDKEY_TEST_NTFS_PATH")
	if root == "" {
		t.Skip("set WARDKEY_TEST_NTFS_PATH to a dedicated directory on an ACL-capable filesystem")
	}

	directory, err := os.MkdirTemp(root, "wardkey-audit-test-")
	if err != nil {
		t.Fatalf("create audit test directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove audit test directory: %v", err)
		}
	})

	return directory
}

//go:build windows

package broker

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"wardkey/internal/audit"
	"wardkey/internal/identity"
	"wardkey/internal/policy"
	"wardkey/internal/vault"
)

func TestCredentialReleaseFailsClosedWhenAuditWriteFails(t *testing.T) {
	root := os.Getenv("WARDKEY_TEST_NTFS_PATH")
	if root == "" {
		t.Skip("set WARDKEY_TEST_NTFS_PATH to a dedicated NTFS test directory")
	}

	testDir, err := os.MkdirTemp(root, "wardkey-broker-audit-failure-")
	if err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	auditPath := filepath.Join(testDir, "audit.jsonl")
	logger, err := audit.NewLogger(auditPath)
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}

	if err := os.WriteFile(auditPath, []byte("tampered\n"), 0600); err != nil {
		t.Fatalf("corrupt test audit log: %v", err)
	}

	auditKey := bytes.Repeat([]byte{0x42}, vault.AuditKeySize)
	session := NewSession()
	if err := session.UnlockWithAuditKey(nil, auditKey); err != nil {
		t.Fatalf("unlock test session: %v", err)
	}
	defer session.Lock()

	handler := NewHandler(policy.Policy{Version: 1}, nil)
	handler.session = session
	if err := handler.SetAuditLogger(logger); err != nil {
		t.Fatalf("configure audit logger: %v", err)
	}

	var callerHash [32]byte
	callerHash[0] = 1
	caller := identity.ProcessIdentity{
		PID:                 1234,
		ImagePath:           `C:\Program Files\Git\bin\git.exe`,
		ImageFileSHA256:     callerHash,
		ProcessCreationTime: 1,
	}
	args := credentialArgs{
		Provider: "github",
		Profile:  "github.com/owner/repo/alice",
	}

	data := json.RawMessage(`{"password":"dummy-secret"}`)
	result, protocolErr := handler.returnCredentialAfterAudit(caller, args, data)
	if protocolErr == nil || protocolErr.Code != "audit_write_failed" {
		t.Fatalf("error = %v, want audit_write_failed", protocolErr)
	}
	if result != nil {
		t.Fatal("credential data was returned despite audit failure")
	}
	for i, value := range data {
		if value != 0 {
			t.Fatalf("credential data byte %d was not cleared", i)
		}
	}
}

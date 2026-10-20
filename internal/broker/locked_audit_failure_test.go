//go:build windows

package broker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"wardkey/internal/audit"
	"wardkey/internal/ipc"
	"wardkey/internal/policy"
	"wardkey/internal/vault"
)

func TestLockedCredentialRequestFailsClosedWhenAuditWriteFails(t *testing.T) {
	root := os.Getenv("WARDKEY_TEST_NTFS_PATH")
	if root == "" {
		t.Skip("set WARDKEY_TEST_NTFS_PATH to a dedicated NTFS test directory")
	}

	testDir, err := os.MkdirTemp(root, "wardkey-locked-audit-failure-")
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

	handler := NewHandler(policy.Policy{Version: 1}, nil)
	defer handler.Close()

	if err := handler.SetAuditLogger(logger); err != nil {
		t.Fatalf("configure audit logger: %v", err)
	}

	auditKey := make([]byte, vault.AuditKeySize)
	for i := range auditKey {
		auditKey[i] = 0x42
	}
	if err := handler.UnlockWithAuditKey(nil, auditKey); err != nil {
		t.Fatalf("unlock test session: %v", err)
	}
	handler.Lock()

	args, err := json.Marshal(credentialArgs{
		Provider: "github",
		Profile:  "github.com/owner/repo/alice",
	})
	if err != nil {
		t.Fatalf("encode request arguments: %v", err)
	}

	data, protocolErr := handler.handleCredentialRequest(
		context.Background(),
		uint32(os.Getpid()),
		ipc.Request{
			Op:   ipc.OpGetCred,
			Args: args,
		},
	)
	if protocolErr == nil || protocolErr.Code != "audit_write_failed" {
		t.Fatalf("error = %v, want audit_write_failed", protocolErr)
	}
	if data != nil {
		t.Fatal("credential data was returned despite audit failure")
	}
	if !handler.session.Locked() {
		t.Fatal("session became unlocked after the failed audit write")
	}
}

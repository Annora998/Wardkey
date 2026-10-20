//go:build windows

package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wardkey/internal/audit"
	"wardkey/internal/ipc"
	"wardkey/internal/vault"
)

func TestLockedCredentialRequestIsAudited(t *testing.T) {
	root := os.Getenv("WARDKEY_TEST_NTFS_PATH")
	if root == "" {
		t.Skip("set WARDKEY_TEST_NTFS_PATH to a dedicated NTFS test directory")
	}

	testDir, err := os.MkdirTemp(root, "wardkey-locked-audit-test-")
	if err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	logger, err := audit.NewLogger(filepath.Join(testDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}

	auditKey := bytes.Repeat([]byte{0x5A}, vault.AuditKeySize)
	verifyKey := bytes.Clone(auditKey)
	defer clear(verifyKey)

	handler := NewHandler(policyForAuditTest(), nil)
	defer handler.Close()

	if err := handler.SetAuditLogger(logger); err != nil {
		t.Fatalf("configure audit logger: %v", err)
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

	_, protocolErr := handler.handleCredentialRequest(
		context.Background(),
		uint32(os.Getpid()),
		ipc.Request{
			Op:   ipc.OpGetCred,
			Args: args,
		},
	)
	if protocolErr == nil {
		t.Fatal("locked credential request succeeded; want rejection")
	}
	if protocolErr.Code != "vault_locked" {
		t.Fatalf("error code = %q, want %q", protocolErr.Code, "vault_locked")
	}

	if err := logger.Verify(verifyKey); err != nil {
		t.Fatalf("verify audit log: %v", err)
	}

	logBytes, err := os.ReadFile(filepath.Join(testDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	defer clear(logBytes)

	logText := string(logBytes)
	for _, want := range []string{
		`"type":"credential.request"`,
		`"outcome":"vault_locked"`,
		`"provider":"github"`,
		`"profile":"github.com/owner/repo/alice"`,
		`"caller_file_sha256"`,
	} {
		if !strings.Contains(logText, want) {
			t.Errorf("audit log does not contain %q", want)
		}
	}
	if strings.Contains(logText, "dummy-secret") {
		t.Error("audit log contains a credential value")
	}
}

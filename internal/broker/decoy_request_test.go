//go:build windows

package broker

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wardkey/internal/audit"
	"wardkey/internal/identity"
	"wardkey/internal/policy"
	"wardkey/internal/vault"
)

func TestDecoyCredentialRequestIsAuditedAndDenied(t *testing.T) {
	root := os.Getenv("WARDKEY_TEST_NTFS_PATH")
	if root == "" {
		t.Skip("set WARDKEY_TEST_NTFS_PATH to a dedicated NTFS test directory")
	}

	testDir, err := os.MkdirTemp(root, "wardkey-decoy-test-")
	if err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	logger, err := audit.NewLogger(filepath.Join(testDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}

	const secret = "dummy-decoy-secret"
	entry, err := vault.NewDecoyEntry("generic", "decoy-profile", []byte(secret))
	if err != nil {
		t.Fatalf("create decoy entry: %v", err)
	}

	auditKey := bytes.Repeat([]byte{0x42}, vault.AuditKeySize)
	verifyKey := bytes.Clone(auditKey)
	defer clear(verifyKey)

	handler := NewHandler(policy.Policy{Version: 1}, nil)
	defer handler.Close()

	if err := handler.SetAuditLogger(logger); err != nil {
		t.Fatalf("configure audit logger: %v", err)
	}
	if err := handler.UnlockWithAuditKey([]vault.Entry{entry}, auditKey); err != nil {
		t.Fatalf("unlock test session: %v", err)
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
		Provider: "generic",
		Profile:  "decoy-profile",
	}

	protocolErr := handler.rejectDecoyCredentialRequest(caller, args)
	if protocolErr == nil {
		t.Fatal("decoy request was not denied")
	}
	if protocolErr.Code != "policy_denied" {
		t.Fatalf("error code = %q, want policy_denied", protocolErr.Code)
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
	if !strings.Contains(logText, `"outcome":"decoy_detected"`) {
		t.Error("audit log does not record decoy_detected")
	}
	if strings.Contains(logText, secret) {
		t.Error("audit log contains the decoy value")
	}
}
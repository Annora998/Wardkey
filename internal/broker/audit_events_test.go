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

func TestAppendCredentialAuditRecordsMetadataWithoutSecret(t *testing.T) {
	root := os.Getenv("WARDKEY_TEST_NTFS_PATH")
	if root == "" {
		t.Skip("set WARDKEY_TEST_NTFS_PATH to a dedicated NTFS test directory")
	}

	testDir, err := os.MkdirTemp(root, "wardkey-broker-audit-test-")
	if err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	logger, err := audit.NewLogger(filepath.Join(testDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}

	var callerHash [32]byte
	callerHash[0] = 1

	caller := identity.ProcessIdentity{
		PID:                 1234,
		ImagePath:           `C:\Program Files\Git\bin\git.exe`,
		ImageFileSHA256:     callerHash,
		ProcessCreationTime: 1,
	}

	auditKey := bytes.Repeat([]byte{0x42}, vault.AuditKeySize)
	verifyKey := bytes.Clone(auditKey)

	session := NewSession()
	if err := session.UnlockWithAuditKey(nil, auditKey); err != nil {
		t.Fatalf("unlock test session: %v", err)
	}
	defer session.Lock()

	handler := NewHandler(policyForAuditTest(), nil)
	handler.session = session
	if err := handler.SetAuditLogger(logger); err != nil {
		t.Fatalf("configure audit logger: %v", err)
	}

	args := credentialArgs{
		Provider: "github",
		Profile:  "github.com/owner/repo/alice",
	}
	if err := handler.appendCredentialAudit(caller, args, "denied"); err != nil {
		t.Fatalf("append credential audit event: %v", err)
	}

	if err := logger.Verify(verifyKey); err != nil {
		t.Fatalf("verify audit log: %v", err)
	}
	clear(verifyKey)

	logBytes, err := os.ReadFile(filepath.Join(testDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	defer clear(logBytes)

	logText := string(logBytes)
	for _, want := range []string{
		`"type":"credential.request"`,
		`"outcome":"denied"`,
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

func policyForAuditTest() policy.Policy {
	return policy.Policy{Version: 1}
}

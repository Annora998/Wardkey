package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"wardkey/internal/approval"
	"wardkey/internal/audit"
	"wardkey/internal/config"
	"wardkey/internal/vault"
)

func enrollApproval(out io.Writer) error {
	home, err := config.DefaultHome()
	if err != nil {
		return fmt.Errorf("resolve Wardkey home: %w", err)
	}
	if home.Development {
		if _, err := fmt.Fprintln(out, home.Warning); err != nil {
			return err
		}
	}

	vaultPath := filepath.Join(home.Path, "vault.wkv")
	if _, err := os.Lstat(vaultPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("vault not found; run 'wardkey init' first")
		}
		return fmt.Errorf("inspect vault path: %w", err)
	}

	passphrase, err := readPassphrase("Vault passphrase: ")
	if err != nil {
		return err
	}
	defer clear(passphrase)

	entries, auditKey, approvalKey, err := vault.LoadWithSessionKeys(vaultPath, passphrase)
	if err != nil {
		return fmt.Errorf("unlock vault for approval enrollment: %w", err)
	}
	defer clearCredentialEntries(entries)
	defer clear(auditKey)
	defer clear(approvalKey)

	logger, err := audit.NewLogger(filepath.Join(home.Path, "audit.jsonl"))
	if err != nil {
		return fmt.Errorf("prepare audit log: %w", err)
	}
	if err := logger.Verify(auditKey); err != nil {
		return fmt.Errorf("verify audit log before approval enrollment: %w", err)
	}

	store, err := approval.NewStore(filepath.Join(home.Path, "approval.json"))
	if err != nil {
		return fmt.Errorf("prepare approval enrollment store: %w", err)
	}

	if err := logger.Append(auditKey, audit.Event{
		Type:    "approval.enroll",
		Outcome: "started",
	}); err != nil {
		return fmt.Errorf("record approval enrollment start: %w", err)
	}

	enrollErr := approval.Enroll(store, approvalKey)
	outcome := "success"
	if enrollErr != nil {
		outcome = "failed"
	}
	if err := logger.Append(auditKey, audit.Event{
		Type:    "approval.enroll",
		Outcome: outcome,
	}); err != nil {
		if enrollErr != nil {
			return errors.Join(
				fmt.Errorf("enroll Windows Hello approval: %w", enrollErr),
				fmt.Errorf("record approval enrollment result: %w", err),
			)
		}
		return fmt.Errorf("approval enrollment may have completed, but its result could not be recorded: %w", err)
	}
	if enrollErr != nil {
		return fmt.Errorf("enroll Windows Hello approval: %w", enrollErr)
	}

	_, err = fmt.Fprintln(out, "Windows Hello approval enrolled.")
	return err
}

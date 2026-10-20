package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"wardkey/internal/audit"
	"wardkey/internal/config"
	"wardkey/internal/vault"
)

func verifyAuditLog(out io.Writer) error {
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
			return errors.New("vault not found")
		}
		return fmt.Errorf("inspect vault path: %w", err)
	}

	auditPath := filepath.Join(home.Path, "audit.jsonl")
	if _, err := os.Lstat(auditPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("audit log not found")
		}
		return fmt.Errorf("inspect audit log path: %w", err)
	}

	passphrase, err := readPassphrase("Vault passphrase: ")
	if err != nil {
		return err
	}
	defer clear(passphrase)

	entries, auditKey, err := vault.LoadWithAuditKey(vaultPath, passphrase)
	if err != nil {
		return fmt.Errorf("unlock vault for audit verification: %w", err)
	}
	defer clearCredentialEntries(entries)
	defer clear(auditKey)

	logger, err := audit.NewLogger(auditPath)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	if err := logger.Verify(auditKey); err != nil {
		return fmt.Errorf("audit log verification failed: %w", err)
	}

	_, err = fmt.Fprintln(out, "Audit log integrity verified.")
	return err
}

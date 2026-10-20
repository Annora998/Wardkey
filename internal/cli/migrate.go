package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"wardkey/internal/config"
	"wardkey/internal/vault"
)

func migrateVault(out io.Writer) error {
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
			return errors.New("vault not found; nothing to migrate")
		}
		return fmt.Errorf("inspect vault path: %w", err)
	}

	passphrase, err := readPassphrase("Vault passphrase: ")
	if err != nil {
		return err
	}
	defer clear(passphrase)

	entries, err := vault.Load(vaultPath, passphrase)
	if err != nil {
		return fmt.Errorf("open vault for migration: %w", err)
	}
	defer clearCredentialEntries(entries)

	if err := vault.Save(vaultPath, entries, passphrase); err != nil {
		return fmt.Errorf("save migrated vault: %w", err)
	}

	_, err = fmt.Fprintln(out, "Vault migrated to the current encrypted format.")
	return err
}

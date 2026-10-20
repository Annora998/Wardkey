package cli

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"wardkey/internal/config"
	"wardkey/internal/vault"
)

func initializeVault(out io.Writer) error {
	home, err := config.DefaultHome()
	if err != nil {
		return fmt.Errorf("resolve Wardkey home: %w", err)
	}

	vaultPath := filepath.Join(home.Path, "vault.wkv")
	if err := vault.CheckStorageFilesystem(vaultPath); err != nil {
		return fmt.Errorf("vault storage filesystem check failed: %w", err)
	}

	if _, err := os.Lstat(vaultPath); err == nil {
		return vault.ErrVaultAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect vault path: %w", err)
	}

	if home.Development {
		if _, err := fmt.Fprintln(out, home.Warning); err != nil {
			return err
		}
	}

	passphrase, err := readPassphrase("New vault passphrase: ")
	if err != nil {
		return err
	}
	defer clear(passphrase)

	if len(passphrase) < 12 {
		return errors.New("passphrase must be at least 12 bytes")
	}

	confirmation, err := readPassphrase("Confirm vault passphrase: ")
	if err != nil {
		return err
	}
	defer clear(confirmation)

	if subtle.ConstantTimeCompare(passphrase, confirmation) != 1 {
		return errors.New("passphrases do not match")
	}

	if err := vault.Create(vaultPath, []vault.Entry{}, passphrase); err != nil {
		return fmt.Errorf("initialize vault: %w", err)
	}

	_, err = fmt.Fprintln(out, "Vault created.")
	return err
}

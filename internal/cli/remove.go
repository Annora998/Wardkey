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

func removeCredential(args []string, out io.Writer) error {
	if len(args) != 3 || args[1] == "" || args[2] == "" {
		return errors.New("usage: wardkey remove <provider> <name>")
	}

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

	entries, dataKey, err := vault.LoadWithDataKey(vaultPath, passphrase)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}
	defer clear(dataKey)
	defer clearCredentialEntries(entries)

	index := -1
	for i := range entries {
		if entries[i].Provider == args[1] && entries[i].Name == args[2] {
			index = i
			break
		}
	}
	if index == -1 {
		return errors.New("no credential with that provider and name exists")
	}

	clear(entries[index].Value)
	copy(entries[index:], entries[index+1:])
	entries[len(entries)-1] = vault.Entry{}
	entries = entries[:len(entries)-1]

	if err := vault.SaveWithDataKey(vaultPath, entries, passphrase, dataKey); err != nil {
		return fmt.Errorf("save updated vault: %w", err)
	}

	_, err = fmt.Fprintln(out, "Credential removed from the vault.")
	return err
}

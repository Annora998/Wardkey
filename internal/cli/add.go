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

func addCredential(args []string, out io.Writer) error {
	var provider, name string
	decoy := false

	switch {
	case len(args) == 3 && args[1] != "" && args[2] != "":
		provider, name = args[1], args[2]

	case len(args) == 4 && args[1] == "--decoy" && args[2] != "" && args[3] != "":
		provider, name = args[2], args[3]
		decoy = true

	default:
		return errors.New("usage: wardkey add [--decoy] <provider> <name>")
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

	for _, existing := range entries {
		if existing.Provider == provider && existing.Name == name {
			return errors.New("a credential with that provider and name already exists")
		}
	}

	value, err := readPassphrase("Credential value (input hidden): ")
	if err != nil {
		return err
	}
	defer clear(value)

	var entry vault.Entry
	if decoy {
		entry, err = vault.NewDecoyEntry(provider, name, value)
	} else {
		entry, err = vault.NewEntry(provider, name, value)
	}
	if err != nil {
		return fmt.Errorf("validate credential: %w", err)
	}

	entries = append(entries, entry)
	if err := vault.SaveWithDataKey(vaultPath, entries, passphrase, dataKey); err != nil {
		return fmt.Errorf("save credential: %w", err)
	}

	message := "Credential saved encrypted in the vault."
	if decoy {
		message = "Decoy saved encrypted in the vault."
	}
	_, err = fmt.Fprintln(out, message)
	return err
}

func clearCredentialEntries(entries []vault.Entry) {
	for i := range entries {
		clear(entries[i].Value)
		entries[i] = vault.Entry{}
	}
}

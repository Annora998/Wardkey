package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"wardkey/internal/config"
	"wardkey/internal/vault"
)

func listCredentials(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("'list' does not accept additional arguments")
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

	entries, err := vault.Load(vaultPath, passphrase)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}
	defer clearCredentialEntries(entries)

	if len(entries) == 0 {
		_, err := fmt.Fprintln(out, "Vault is empty.")
		return err
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Provider != entries[j].Provider {
			return entries[i].Provider < entries[j].Provider
		}
		return entries[i].Name < entries[j].Name
	})

	if _, err := fmt.Fprintln(out, "Provider\tName\tKind\tCreated (UTC)"); err != nil {
		return err
	}
	for _, entry := range entries {
		kind := "credential"
		if entry.Decoy {
			kind = "decoy"
		}
		if _, err := fmt.Fprintf(
			out,
			"%s\t%s\t%s\t%s\n",
			entry.Provider,
			entry.Name,
			kind,
			entry.CreatedAt.UTC().Format(time.RFC3339),
		); err != nil {
			return err
		}
	}

	return nil
}

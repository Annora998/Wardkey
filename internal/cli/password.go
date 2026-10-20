package cli

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

func readPassphrase(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("passphrase input requires an interactive terminal")
	}

	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return nil, fmt.Errorf("write passphrase prompt: %w", err)
	}

	passphrase, err := term.ReadPassword(fd)
	_, newlineErr := fmt.Fprintln(os.Stderr)

	if err != nil {
		clear(passphrase)
		return nil, fmt.Errorf("read passphrase without echo: %w", err)
	}
	if newlineErr != nil {
		clear(passphrase)
		return nil, fmt.Errorf("finish passphrase prompt: %w", newlineErr)
	}

	return passphrase, nil
}

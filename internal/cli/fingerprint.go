package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"wardkey/internal/identity"
)

func showFingerprint(args []string, out io.Writer) error {
	if len(args) != 2 || args[1] == "" {
		return errors.New("usage: wardkey fingerprint <executable-path>")
	}

	digest, err := identity.FingerprintFile(args[1])
	if err != nil {
		return fmt.Errorf("fingerprint executable: %w", err)
	}

	_, err = fmt.Fprintf(out, "Policy who: file-sha256:%s\n", hex.EncodeToString(digest[:]))
	return err
}

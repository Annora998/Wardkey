//go:build !windows

package vault

import "errors"

func readVaultFile(string) ([]byte, error) {
	return nil, errors.New("secure vault storage is supported only on Windows")
}

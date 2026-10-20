//go:build !windows

package vault

import "errors"

func writeVaultAtomically(string, []byte) error {
	return errors.New("secure vault storage is supported only on Windows")
}

func createVaultAtomically(string, []byte) error {
	return errors.New("secure vault storage is supported only on Windows")
}

//go:build !windows

package vault

// Non-Windows builds cannot yet verify the vault filesystem's ACL support.
func requireACLFilesystem(string) error {
	return ErrACLsRequired
}

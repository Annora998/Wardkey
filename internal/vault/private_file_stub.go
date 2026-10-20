//go:build !windows

package vault

// RestrictExistingPrivateFile is unsupported outside Windows.
func RestrictExistingPrivateFile(string) error {
	return ErrACLsRequired
}

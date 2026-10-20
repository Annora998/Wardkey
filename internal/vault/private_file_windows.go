//go:build windows

package vault

// RestrictExistingPrivateFile protects an existing regular file so only the
// current Windows user has access. It rejects directories and reparse points.
func RestrictExistingPrivateFile(path string) error {
	return restrictExistingVaultFile(path)
}

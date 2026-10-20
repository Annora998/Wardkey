//go:build !windows

package vault

// Directory security is unsupported outside Windows in this build.
func ensurePrivateDirectory(string) error {
	return ErrACLsRequired
}

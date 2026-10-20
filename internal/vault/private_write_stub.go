//go:build !windows

package vault

// CreatePrivateFileAtomically is unsupported outside Windows.
func CreatePrivateFileAtomically(string, []byte) error {
	return ErrACLsRequired
}

// ReplacePrivateFileAtomically is unsupported outside Windows.
func ReplacePrivateFileAtomically(string, []byte) error {
	return ErrACLsRequired
}

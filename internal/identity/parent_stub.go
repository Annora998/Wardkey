//go:build !windows

package identity

// ParentProcessID is available only in the Windows build.
func ParentProcessID(uint32) (uint32, error) {
	return 0, ErrInvalidIdentity
}

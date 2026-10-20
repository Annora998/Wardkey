package vault

// EnsurePrivateDirectory creates or secures a private application directory.
// On Windows it applies the current-user ACL; other platforms return
// ErrACLsRequired in this build.
func EnsurePrivateDirectory(path string) error {
	return ensurePrivateDirectory(path)
}

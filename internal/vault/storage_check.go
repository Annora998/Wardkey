package vault

import (
	"errors"
	"strings"
)

// CheckStorageFilesystem checks ACL support without creating or changing files.
func CheckStorageFilesystem(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("vault path is empty")
	}
	return requireACLFilesystem(path)
}

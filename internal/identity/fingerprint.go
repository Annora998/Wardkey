package identity

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FingerprintFile returns the SHA-256 digest of a regular executable file.
// The result is informational; the broker still inspects the connecting process.
func FingerprintFile(path string) ([32]byte, error) {
	if strings.TrimSpace(path) == "" {
		return [32]byte{}, errors.New("executable path is required")
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("resolve executable path: %w", err)
	}

	info, err := os.Lstat(absolute)
	if err != nil {
		return [32]byte{}, fmt.Errorf("inspect executable path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return [32]byte{}, errors.New("executable path is not a regular file")
	}

	file, err := os.Open(absolute)
	if err != nil {
		return [32]byte{}, fmt.Errorf("open executable file: %w", err)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return [32]byte{}, fmt.Errorf("inspect opened executable: %w", err)
	}
	if !openedInfo.Mode().IsRegular() {
		return [32]byte{}, errors.New("opened executable is not a regular file")
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return [32]byte{}, fmt.Errorf("hash executable file: %w", err)
	}

	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

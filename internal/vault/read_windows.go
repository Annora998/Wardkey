//go:build windows

package vault

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const maxVaultFileBytes = 16 << 20

func readVaultFile(path string) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve vault path: %w", err)
	}

	if err := ensurePrivateDirectory(filepath.Dir(absolute)); err != nil {
		return nil, err
	}
	if err := restrictExistingVaultFile(absolute); err != nil {
		return nil, err
	}

	pathPtr, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return nil, errors.New("encode vault path")
	}
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return nil, fmt.Errorf("inspect vault file: %w", err)
	}
	if attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("vault path is not a regular file")
	}

	file, err := os.Open(absolute)
	if err != nil {
		return nil, fmt.Errorf("open vault file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open vault file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("vault path is not a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxVaultFileBytes {
		return nil, errors.New("vault file size is outside the allowed range")
	}

	data, err := io.ReadAll(io.LimitReader(file, maxVaultFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read vault file: %w", err)
	}
	if len(data) == 0 || len(data) > maxVaultFileBytes {
		return nil, errors.New("vault file size is outside the allowed range")
	}
	if int64(len(data)) != info.Size() {
		return nil, errors.New("vault file changed while being read")
	}

	return data, nil
}

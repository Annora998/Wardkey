//go:build windows

package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const maxPrivateFileBytes = 1 << 20

var ErrPrivateFileAlreadyExists = errors.New("private file already exists")

// CreatePrivateFileAtomically creates a private file without overwriting an
// existing file. The file is restricted to the current Windows user.
func CreatePrivateFileAtomically(path string, data []byte) error {
	return writePrivateFileAtomically(path, data, false)
}

// ReplacePrivateFileAtomically atomically replaces an existing private regular
// file. It rejects directories and reparse points.
func ReplacePrivateFileAtomically(path string, data []byte) error {
	return writePrivateFileAtomically(path, data, true)
}

func writePrivateFileAtomically(path string, data []byte, replace bool) error {
	if len(data) == 0 {
		return errors.New("refusing to write an empty private file")
	}
	if len(data) > maxPrivateFileBytes {
		return errors.New("private file exceeds the 1 MiB limit")
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve private file path: %w", err)
	}

	dir := filepath.Dir(absolute)
	if err := ensurePrivateDirectory(dir); err != nil {
		return err
	}

	if replace {
		info, err := os.Lstat(absolute)
		if err != nil {
			return fmt.Errorf("inspect private file to replace: %w", err)
		}
		if !info.Mode().IsRegular() {
			return errors.New("private file path is not a regular file")
		}
		if err := restrictExistingVaultFile(absolute); err != nil {
			return err
		}
	}

	temp, err := os.CreateTemp(dir, ".wardkey-private-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary private file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := restrictExistingVaultFile(tempPath); err != nil {
		_ = temp.Close()
		return fmt.Errorf("restrict temporary private file: %w", err)
	}

	n, err := temp.Write(data)
	if err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary private file: %w", err)
	}
	if n != len(data) {
		_ = temp.Close()
		return errors.New("write temporary private file: incomplete write")
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("flush temporary private file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary private file: %w", err)
	}

	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return errors.New("encode temporary private file path")
	}
	to, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return errors.New("encode private file path")
	}

	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}

	if err := windows.MoveFileEx(from, to, flags); err != nil {
		if !replace &&
			(errors.Is(err, windows.ERROR_ALREADY_EXISTS) ||
				errors.Is(err, windows.ERROR_FILE_EXISTS)) {
			return ErrPrivateFileAlreadyExists
		}
		return fmt.Errorf("move temporary private file into place: %w", err)
	}

	return nil
}

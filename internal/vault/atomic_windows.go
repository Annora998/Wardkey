//go:build windows

package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func writeVaultAtomically(path string, encryptedData []byte) error {
	return writeVaultFileAtomically(path, encryptedData, true)
}

func createVaultAtomically(path string, encryptedData []byte) error {
	return writeVaultFileAtomically(path, encryptedData, false)
}

func writeVaultFileAtomically(path string, encryptedData []byte, replace bool) error {
	if len(encryptedData) == 0 {
		return errors.New("refusing to write an empty vault")
	}
	if len(encryptedData) > maxVaultFileBytes {
		return errors.New("encrypted vault exceeds the 16 MiB limit")
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve vault path: %w", err)
	}

	dir := filepath.Dir(absolute)
	if err := ensurePrivateDirectory(dir); err != nil {
		return err
	}

	temp, err := os.CreateTemp(dir, ".wardkey-vault-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary vault file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	n, err := temp.Write(encryptedData)
	if err != nil {
		temp.Close()
		return fmt.Errorf("write temporary vault file: %w", err)
	}
	if n != len(encryptedData) {
		temp.Close()
		return errors.New("write temporary vault file: incomplete write")
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("flush temporary vault file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary vault file: %w", err)
	}

	if replace {
		if err := restrictExistingVaultFile(absolute); err != nil {
			return err
		}
	}

	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return errors.New("encode temporary vault path")
	}
	to, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return errors.New("encode vault path")
	}

	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}

	if err := windows.MoveFileEx(from, to, flags); err != nil {
		if !replace &&
			(errors.Is(err, windows.ERROR_ALREADY_EXISTS) ||
				errors.Is(err, windows.ERROR_FILE_EXISTS)) {
			return ErrVaultAlreadyExists
		}
		return fmt.Errorf("move temporary vault file into place: %w", err)
	}

	return nil
}

func restrictExistingVaultFile(path string) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("encode vault path")
	}

	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
			errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("inspect existing vault file: %w", err)
	}

	if attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("existing vault path is not a regular file")
	}

	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current user SID: %w", err)
	}
	sid := tokenUser.User.Sid.String()
	if sid == "" {
		return errors.New("format current user SID: empty SID")
	}

	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;;FA;;;" + sid + ")",
	)
	if err != nil {
		return fmt.Errorf("create vault file security descriptor: %w", err)
	}

	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read vault file DACL: %w", err)
	}

	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("set vault file permissions: %w", err)
	}

	return nil
}

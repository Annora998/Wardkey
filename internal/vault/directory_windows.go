package vault

import (
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ensurePrivateDirectory(path string) error {
	if err := requireACLFilesystem(path); err != nil {
		return err
	}

	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Dir(absolute) == absolute {
		return errors.New("invalid vault directory path")
	}

	pathPtr, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return errors.New("encode vault directory path")
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
		"D:P(A;OICI;FA;;;" + sid + ")",
	)
	if err != nil {
		return fmt.Errorf("create vault directory security descriptor: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read vault directory DACL: %w", err)
	}

	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}

	createErr := windows.CreateDirectory(pathPtr, &attributes)
	if createErr != nil && !errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("create vault directory: %w", createErr)
	}

	fileAttributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return fmt.Errorf("inspect vault directory: %w", err)
	}
	if fileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		fileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("vault path is not a regular directory")
	}

	if err := windows.SetNamedSecurityInfo(
		absolute,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("set vault directory permissions: %w", err)
	}

	return nil
}

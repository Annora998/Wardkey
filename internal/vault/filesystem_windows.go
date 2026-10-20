package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func requireACLFilesystem(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("vault path is required")
	}

	existing, err := existingPath(path)
	if err != nil {
		return err
	}

	absolute, err := filepath.Abs(existing)
	if err != nil {
		return errors.New("resolve vault path")
	}

	fileName, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return errors.New("encode vault path")
	}

	var volumeRoot [1024]uint16
	if err := windows.GetVolumePathName(fileName, &volumeRoot[0], uint32(len(volumeRoot))); err != nil {
		return errors.New("find vault filesystem")
	}

	var volumeName [256]uint16
	var fileSystemName [64]uint16
	var serialNumber uint32
	var maxComponentLength uint32
	var fileSystemFlags uint32

	if err := windows.GetVolumeInformation(
		&volumeRoot[0],
		&volumeName[0],
		uint32(len(volumeName)),
		&serialNumber,
		&maxComponentLength,
		&fileSystemFlags,
		&fileSystemName[0],
		uint32(len(fileSystemName)),
	); err != nil {
		return errors.New("read vault filesystem capabilities")
	}

	return checkACLFlags(fileSystemFlags)
}

func existingPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("resolve vault path")
	}

	for {
		info, err := os.Stat(absolute)
		if err == nil {
			if info.IsDir() {
				return absolute, nil
			}
			return filepath.Dir(absolute), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", errors.New("inspect vault path")
		}

		parent := filepath.Dir(absolute)
		if parent == absolute {
			return "", errors.New("no existing parent for vault path")
		}
		absolute = parent
	}
}

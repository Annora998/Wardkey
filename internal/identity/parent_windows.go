//go:build windows

package identity

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ParentProcessID returns the parent PID recorded by Windows for pid.
// The broker must still inspect and validate the parent before trusting it.
func ParentProcessID(pid uint32) (uint32, error) {
	if pid == 0 {
		return 0, ErrInvalidIdentity
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(
		windows.TH32CS_SNAPPROCESS,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("snapshot Windows processes: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var process windows.ProcessEntry32
	process.Size = uint32(unsafe.Sizeof(process))

	if err := windows.Process32First(snapshot, &process); err != nil {
		return 0, fmt.Errorf("read Windows process list: %w", err)
	}

	for {
		if process.ProcessID == pid {
			parentPID := process.ParentProcessID
			if parentPID == 0 || parentPID == pid {
				return 0, ErrInvalidIdentity
			}
			return parentPID, nil
		}

		if err := windows.Process32Next(snapshot, &process); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return 0, fmt.Errorf("read Windows process list: %w", err)
		}
	}

	return 0, fmt.Errorf("%w: process %d was not found", ErrInvalidIdentity, pid)
}

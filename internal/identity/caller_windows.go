//go:build windows

package identity

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
)

type windowsProcess struct {
	handle    windows.Handle
	identity  ProcessIdentity
	closeOnce sync.Once
	closeErr  error
}

// OpenProcessIdentity inspects a process and keeps its Windows process handle
// open until Close is called. The image hash is of the executable currently
// present at the process image path.
func OpenProcessIdentity(pid uint32) (InspectedProcess, error) {
	if pid == 0 {
		return nil, ErrInvalidIdentity
	}

	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return nil, fmt.Errorf("open caller process %d: %w", pid, err)
	}

	keepHandle := false
	defer func() {
		if !keepHandle {
			_ = windows.CloseHandle(handle)
		}
	}()

	var creationTime windows.Filetime
	var exitTime windows.Filetime
	var kernelTime windows.Filetime
	var userTime windows.Filetime
	if err := windows.GetProcessTimes(
		handle,
		&creationTime,
		&exitTime,
		&kernelTime,
		&userTime,
	); err != nil {
		return nil, fmt.Errorf("read caller process %d creation time: %w", pid, err)
	}

	processCreationTime := uint64(creationTime.HighDateTime)<<32 |
		uint64(creationTime.LowDateTime)
	if processCreationTime == 0 {
		return nil, errors.New("Windows returned an invalid caller process creation time")
	}

	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return nil, fmt.Errorf("read caller process %d image path: %w", pid, err)
	}
	if size == 0 || int(size) > len(buffer) {
		return nil, errors.New("Windows returned an invalid caller image path")
	}

	imagePath := filepath.Clean(windows.UTF16ToString(buffer[:size]))
	if !filepath.IsAbs(imagePath) {
		return nil, errors.New("Windows returned a non-absolute caller image path")
	}

	file, err := os.Open(imagePath)
	if err != nil {
		return nil, fmt.Errorf("open caller executable: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect caller executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("caller executable is not a regular file")
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, fmt.Errorf("hash caller executable: %w", err)
	}

	var digest [32]byte
	copy(digest[:], hash.Sum(nil))

	processIdentity := ProcessIdentity{
		PID:                 pid,
		ImagePath:           imagePath,
		ImageFileSHA256:     digest,
		ProcessCreationTime: processCreationTime,
	}
	if err := processIdentity.Validate(); err != nil {
		return nil, fmt.Errorf("validate caller identity: %w", err)
	}

	keepHandle = true
	return &windowsProcess{
		handle:   handle,
		identity: processIdentity,
	}, nil
}

// InspectProcess returns process facts and closes the process handle immediately.
// Use OpenProcessIdentity when the handle must stay open during checks.
func InspectProcess(pid uint32) (ProcessIdentity, error) {
	process, err := OpenProcessIdentity(pid)
	if err != nil {
		return ProcessIdentity{}, err
	}
	defer process.Close()

	return process.Identity(), nil
}

func (p *windowsProcess) Identity() ProcessIdentity {
	return p.identity
}

func (p *windowsProcess) Close() error {
	if p == nil {
		return nil
	}

	p.closeOnce.Do(func() {
		if p.handle != 0 {
			p.closeErr = windows.CloseHandle(p.handle)
			p.handle = 0
		}
	})
	return p.closeErr
}

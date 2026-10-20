//go:build !windows

package identity

import "errors"

// OpenProcessIdentity is available only in the Windows build.
func OpenProcessIdentity(uint32) (InspectedProcess, error) {
	return nil, errors.New("process inspection is supported only on Windows")
}

// InspectProcess is available only in the Windows build.
func InspectProcess(uint32) (ProcessIdentity, error) {
	return ProcessIdentity{}, errors.New("process inspection is supported only on Windows")
}

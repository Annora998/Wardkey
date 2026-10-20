package identity

import (
	"errors"
	"path/filepath"
)

var ErrInvalidIdentity = errors.New("invalid process identity")

// ProcessIdentity contains facts gathered by Wardkey's platform inspector.
// A request message must never be used to fill these fields.
type ProcessIdentity struct {
	PID                 uint32
	ImagePath           string
	ImageFileSHA256     [32]byte
	ProcessCreationTime uint64 // Windows FILETIME ticks, captured from the process handle.
}

// InspectedProcess holds an OS process reference while Wardkey uses its identity.
type InspectedProcess interface {
	Identity() ProcessIdentity
	Close() error
}

// Validate rejects identities that are incomplete or not fully qualified.
func (p ProcessIdentity) Validate() error {
	if p.PID == 0 ||
		p.ImagePath == "" ||
		!filepath.IsAbs(p.ImagePath) ||
		p.ProcessCreationTime == 0 {
		return ErrInvalidIdentity
	}
	if p.ImageFileSHA256 == [32]byte{} {
		return ErrInvalidIdentity
	}
	return nil
}

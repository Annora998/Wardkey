package platform

import (
	"context"
	"errors"
	"time"
)

var ErrUnsupported = errors.New("platform capability is unsupported")

// ProcessInfo contains facts collected by the operating system.
// ParentPID is advisory only and must never grant access by itself.
type ProcessInfo struct {
	PID             uint32
	CreationTime    time.Time
	ImagePath       string
	ImageFileSHA256 [32]byte
	Signer          string
	ParentPID       uint32
}

type ProcessInspector interface {
	Inspect(ctx context.Context, pid uint32) (ProcessInfo, error)
}

type KeyWrapper interface {
	Wrap(ctx context.Context, key []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

type ApprovalRequest struct {
	Challenge        [32]byte
	Provider         string
	Profile          string
	Scope            string
	CommandLine      string
	WorkingDirectory string
}

type ApprovalProof struct {
	Assurance string
	Data      []byte
}

type Approver interface {
	Approve(ctx context.Context, request ApprovalRequest) (ApprovalProof, error)
}

type Sandboxer interface {
	Run(ctx context.Context, label string, executable string, args []string) error
}

package stub

import (
	"context"

	"wardkey/internal/platform"
)

type Unsupported struct{}

var (
	_ platform.ProcessInspector = Unsupported{}
	_ platform.KeyWrapper       = Unsupported{}
	_ platform.Approver         = Unsupported{}
	_ platform.Sandboxer        = Unsupported{}
)

func (Unsupported) Inspect(context.Context, uint32) (platform.ProcessInfo, error) {
	return platform.ProcessInfo{}, platform.ErrUnsupported
}

func (Unsupported) Wrap(context.Context, []byte) ([]byte, error) {
	return nil, platform.ErrUnsupported
}

func (Unsupported) Unwrap(context.Context, []byte) ([]byte, error) {
	return nil, platform.ErrUnsupported
}

func (Unsupported) Approve(context.Context, platform.ApprovalRequest) (platform.ApprovalProof, error) {
	return platform.ApprovalProof{}, platform.ErrUnsupported
}

func (Unsupported) Run(context.Context, string, string, []string) error {
	return platform.ErrUnsupported
}

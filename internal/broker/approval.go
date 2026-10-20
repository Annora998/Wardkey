package broker

import (
	"context"

	"wardkey/internal/identity"
	"wardkey/internal/ipc"
)

// CredentialApprovalRequest describes the exact request waiting for approval.
// It contains no credential value.
type CredentialApprovalRequest struct {
	RequestID string
	Operation ipc.Operation
	Provider  string
	Profile   string
	Caller    identity.ProcessIdentity
}

// ApprovalProvider asks a human to approve or deny one credential request.
//
// Approval applies only to the request passed to this call. Implementations
// must not save or reuse an approval for a later request.
type ApprovalProvider interface {
	Approve(
		ctx context.Context,
		request CredentialApprovalRequest,
	) (approved bool, err error)
}
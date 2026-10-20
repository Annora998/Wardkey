package broker

import (
	"context"
	"errors"

	"wardkey/internal/approval"
)

type WebAuthnApprovalProvider struct {
	session *Session
	store   *approval.Store
}

func NewWebAuthnApprovalProvider(
	session *Session,
	store *approval.Store,
) *WebAuthnApprovalProvider {
	return &WebAuthnApprovalProvider{
		session: session,
		store:   store,
	}
}

func (p *WebAuthnApprovalProvider) Approve(
	ctx context.Context,
	request CredentialApprovalRequest,
) (bool, error) {
	if p == nil || p.session == nil {
		return false, errors.New("broker approval session is unavailable")
	}
	if p.store == nil {
		return false, errors.New("approval enrollment store is unavailable")
	}

	var approved bool
	err := p.session.WithApprovalKey(func(approvalKey []byte) error {
		var err error
		approved, err = approval.Approve(ctx, p.store, approvalKey, approval.Request{
			RequestID: request.RequestID,
			Operation: request.Operation,
			Provider:  request.Provider,
			Profile:   request.Profile,
			Caller:    request.Caller,
			RPID:      approval.RPID,
		})
		return err
	})
	if err != nil {
		return false, err
	}

	return approved, nil
}

func (h *Handler) SetWindowsHelloApprovalStore(store *approval.Store) error {
	if h == nil || h.session == nil {
		return errors.New("broker session is unavailable")
	}
	if store == nil {
		return errors.New("approval enrollment store is unavailable")
	}

	return h.SetApprovalProvider(NewWebAuthnApprovalProvider(h.session, store))
}

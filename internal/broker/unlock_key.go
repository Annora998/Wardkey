package broker

import (
	"errors"

	"wardkey/internal/vault"
)

// UnlockWithAuditKey transfers ownership of entries and the audit key to the
// broker session if it succeeds.
func (h *Handler) UnlockWithAuditKey(entries []vault.Entry, auditKey []byte) error {
	if h == nil || h.session == nil {
		return errors.New("broker session is unavailable")
	}
	return h.session.UnlockWithAuditKey(entries, auditKey)
}

// UnlockWithKeys transfers ownership of entries, the audit key, and the
// approval key to the broker session if it succeeds.
func (h *Handler) UnlockWithKeys(
	entries []vault.Entry,
	auditKey []byte,
	approvalKey []byte,
) error {
	if h == nil || h.session == nil {
		return errors.New("broker session is unavailable")
	}
	return h.session.UnlockWithKeys(entries, auditKey, approvalKey)
}

package broker

import (
	"errors"

	"wardkey/internal/identity"
	"wardkey/internal/ipc"
)

func (h *Handler) rejectDecoyCredentialRequest(
	caller identity.ProcessIdentity,
	args credentialArgs,
) *ipc.ProtocolError {
	if h == nil || h.session == nil {
		return protocolError("internal_error", "broker session is unavailable")
	}

	isDecoy, err := h.session.IsDecoy(args.Provider, args.Profile)
	if err != nil {
		if errors.Is(err, ErrSessionLocked) {
			if auditErr := h.appendCredentialAudit(caller, args, "vault_locked"); auditErr != nil {
				return protocolError("audit_write_failed", "Wardkey could not record the locked credential request")
			}
			return protocolError("vault_locked", "the vault is locked")
		}
		return protocolError("internal_error", "Wardkey could not inspect the credential")
	}
	if !isDecoy {
		return nil
	}

	if err := h.appendCredentialAudit(caller, args, "decoy_detected"); err != nil {
		return protocolError("audit_write_failed", "Wardkey could not record the decoy request")
	}
	return protocolError("policy_denied", "policy denied this credential request")
}
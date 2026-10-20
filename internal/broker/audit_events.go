package broker

import (
	"encoding/hex"
	"errors"

	"wardkey/internal/audit"
	"wardkey/internal/identity"
	"wardkey/internal/ipc"
)

func (h *Handler) appendCredentialAudit(
	caller identity.ProcessIdentity,
	args credentialArgs,
	outcome string,
) error {
	if h == nil {
		return errors.New("broker handler is unavailable")
	}
	if err := caller.Validate(); err != nil {
		return errors.New("cannot audit an unverified caller")
	}
	if outcome == "" {
		return errors.New("credential audit outcome is required")
	}

	h.auditMu.RLock()
	logger := h.auditLogger
	h.auditMu.RUnlock()
	if logger == nil {
		return errors.New("broker audit logger is unavailable")
	}
	if h.session == nil {
		return errors.New("broker session is unavailable")
	}

	event := audit.Event{
		Type:             "credential.request",
		Outcome:          outcome,
		Provider:         args.Provider,
		Profile:          args.Profile,
		CallerFileSHA256: hex.EncodeToString(caller.ImageFileSHA256[:]),
	}

	return h.session.WithAuditKey(func(key []byte) error {
		return logger.Append(key, event)
	})
}

func (h *Handler) returnCredentialAfterAudit(
	caller identity.ProcessIdentity,
	args credentialArgs,
	data []byte,
) ([]byte, *ipc.ProtocolError) {
	if err := h.appendCredentialAudit(caller, args, "released"); err != nil {
		clear(data)
		return nil, protocolError(
			"audit_write_failed",
			"Wardkey could not record the credential release",
		)
	}
	return data, nil
}

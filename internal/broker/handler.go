package broker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"wardkey/internal/audit"
	"wardkey/internal/identity"
	"wardkey/internal/ipc"
	"wardkey/internal/policy"
	"wardkey/internal/vault"
)

// OperationExecutor performs an already-authorized operation using one
// credential value. It must use the value synchronously and must not retain it.
type OperationExecutor func(
	ctx context.Context,
	caller identity.ProcessIdentity,
	request ipc.Request,
	credential []byte,
) (json.RawMessage, *ipc.ProtocolError)

// Handler applies caller identity and policy checks to IPC requests.
type Handler struct {
	rules    policy.Policy
	executor OperationExecutor
	session  *Session

	auditMu     sync.RWMutex
	auditLogger *audit.Logger

	approvalMu       sync.RWMutex
	approvalProvider ApprovalProvider
}

// NewHandler creates a broker handler.
func NewHandler(rules policy.Policy, executor OperationExecutor) *Handler {
	return &Handler{
		rules:    rules,
		executor: executor,
		session:  NewSession(),
	}
}

// SetAuditLogger configures the logger before the handler starts serving requests.
func (h *Handler) SetAuditLogger(logger *audit.Logger) error {
	if h == nil {
		return errors.New("broker handler is unavailable")
	}
	if logger == nil {
		return errors.New("audit logger is unavailable")
	}

	h.auditMu.Lock()
	h.auditLogger = logger
	h.auditMu.Unlock()
	return nil
}

// SetApprovalProvider configures the provider before serving requests.
// If no provider is configured, approval-required requests are denied.
func (h *Handler) SetApprovalProvider(provider ApprovalProvider) error {
	if h == nil {
		return errors.New("broker handler is unavailable")
	}
	if provider == nil {
		return errors.New("approval provider is unavailable")
	}

	h.approvalMu.Lock()
	h.approvalProvider = provider
	h.approvalMu.Unlock()
	return nil
}

func (h *Handler) getApprovalProvider() ApprovalProvider {
	if h == nil {
		return nil
	}

	h.approvalMu.RLock()
	provider := h.approvalProvider
	h.approvalMu.RUnlock()
	return provider
}

// Unlock transfers ownership of decrypted entries to the broker session.
func (h *Handler) Unlock(entries []vault.Entry) error {
	if h == nil || h.session == nil {
		return errors.New("broker session is unavailable")
	}
	return h.session.Unlock(entries)
}

// Lock clears the session's decrypted credential values.
func (h *Handler) Lock() {
	if h != nil && h.session != nil {
		h.session.Lock()
	}
}

// Handle processes one request using the peer PID supplied by the named pipe.
func (h *Handler) Handle(
	ctx context.Context,
	peerPID uint32,
	request ipc.Request,
) (json.RawMessage, *ipc.ProtocolError) {
	if h == nil {
		return nil, protocolError("internal_error", "broker handler is unavailable")
	}
	if ctx == nil {
		return nil, protocolError("invalid_request", "request context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, protocolError("request_cancelled", "request was cancelled")
	}
	if err := request.Validate(); err != nil {
		return nil, protocolError("invalid_request", "request is invalid")
	}

	switch request.Op {
	case ipc.OpHello:
		return successData(map[string]any{
			"protocol": ipc.ProtocolVersion,
		})

	case ipc.OpStatus:
		locked := h.session == nil || h.session.Locked()
		return successData(map[string]any{
			"protocol": ipc.ProtocolVersion,
			"locked":   locked,
		})

	case ipc.OpGetCred, ipc.OpGetGitCred:
		return h.handleCredentialRequest(ctx, peerPID, request)

	case ipc.OpLock:
		if err := h.appendLockAudit(); err != nil {
			// Lock even if the audit write fails, so an audit problem cannot
			// leave credentials available in memory.
			h.Lock()
			return nil, protocolError(
				"audit_write_failed",
				"the broker locked, but could not record the lock event",
			)
		}
		h.Lock()
		return successData(map[string]any{
			"locked": true,
		})

	case ipc.OpJobOpen, ipc.OpPanic:
		return nil, protocolError(
			"operation_unavailable",
			"this operation is not implemented yet",
		)

	default:
		return nil, protocolError("unsupported_operation", "operation is not supported")
	}
}

// appendLockAudit records the lock event while the session audit key is still
// available. If no logger is configured, it leaves existing test handlers
// usable; the CLI must configure a logger before serving.
func (h *Handler) appendLockAudit() error {
	h.auditMu.RLock()
	logger := h.auditLogger
	h.auditMu.RUnlock()

	if logger == nil || h.session == nil || h.session.Locked() {
		return nil
	}

	return h.session.WithAuditKey(func(key []byte) error {
		return logger.Append(key, audit.Event{
			Type:    "vault.lock",
			Outcome: "success",
		})
	})
}

func (h *Handler) handleCredentialRequest(
	ctx context.Context,
	peerPID uint32,
	request ipc.Request,
) (json.RawMessage, *ipc.ProtocolError) {
	if h == nil || h.session == nil {
		return nil, protocolError("vault_locked", "the vault is locked")
	}
	if peerPID == 0 {
		return nil, protocolError("invalid_caller", "Windows did not provide a valid caller process")
	}

	args, err := decodeCredentialArgs(request.Args)
	if err != nil {
		return nil, protocolError("invalid_arguments", "credential request arguments are invalid")
	}

	callerProcess, err := identity.OpenProcessIdentity(peerPID)
	if err != nil {
		return nil, protocolError("caller_inspection_failed", "Wardkey could not verify the caller process")
	}
	defer callerProcess.Close()

	caller := callerProcess.Identity()
	if err := caller.Validate(); err != nil {
		return nil, protocolError("caller_inspection_failed", "Wardkey could not verify the caller process")
	}

	if request.Op == ipc.OpGetGitCred || request.Op == ipc.OpGetCred {
		var helperMatches bool

		switch request.Op {
		case ipc.OpGetGitCred:
			helperMatches = isWardkeyGitHelper(caller.ImagePath)

		case ipc.OpGetCred:
			if args.Provider != "aws" {
				return nil, protocolError("invalid_arguments", "AWS credential request arguments are invalid")
			}
			helperMatches = isWardkeyExecutable(caller.ImagePath)
		}

		if !helperMatches {
			return nil, protocolError("invalid_caller", "credential request did not come from Wardkey's helper")
		}

		brokerIdentity, err := identity.InspectProcess(uint32(os.Getpid()))
		if err != nil || brokerIdentity.Validate() != nil ||
			caller.ImageFileSHA256 != brokerIdentity.ImageFileSHA256 {
			return nil, protocolError("invalid_caller", "Wardkey could not verify its credential helper")
		}

		parentPID, err := identity.ParentProcessID(peerPID)
		if err != nil {
			return nil, protocolError("caller_inspection_failed", "Wardkey could not verify the requesting application")
		}

		parentProcess, err := identity.OpenProcessIdentity(parentPID)
		if err != nil {
			return nil, protocolError("caller_inspection_failed", "Wardkey could not verify the requesting application")
		}
		defer parentProcess.Close()

		requestingApplication := parentProcess.Identity()
		if err := requestingApplication.Validate(); err != nil {
			return nil, protocolError("caller_inspection_failed", "Wardkey could not verify the requesting application")
		}
		if requestingApplication.ProcessCreationTime > caller.ProcessCreationTime {
			return nil, protocolError("invalid_caller", "Wardkey could not verify the requesting application")
		}

		switch request.Op {
		case ipc.OpGetGitCred:
			if !isGitExecutable(requestingApplication.ImagePath) {
				return nil, protocolError("invalid_caller", "Git credential requests must come from Git")
			}

		case ipc.OpGetCred:
			if !isAWSCLIExecutable(requestingApplication.ImagePath) {
				return nil, protocolError("invalid_caller", "AWS credential requests must come from AWS CLI")
			}
		}

		// Apply policy, approval, and audit to the actual requesting application.
		caller = requestingApplication
	}

	if protocolErr := h.rejectDecoyCredentialRequest(caller, args); protocolErr != nil {
		return nil, protocolErr
	}

	principal := "file-sha256:" + hex.EncodeToString(caller.ImageFileSHA256[:])
	decision := policy.Evaluate(h.rules, policy.Request{
		Who:      principal,
		Provider: args.Provider,
		Profile:  args.Profile,
	})

	switch decision.Kind {
	case policy.DecisionDeny:
		if err := h.appendCredentialAudit(caller, args, "denied"); err != nil {
			return nil, protocolError("audit_write_failed", "Wardkey could not record the credential decision")
		}
		return nil, protocolError("policy_denied", "policy denied this credential request")

	case policy.DecisionApproval:
		provider := h.getApprovalProvider()
		if provider == nil {
			if err := h.appendCredentialAudit(caller, args, "approval_required"); err != nil {
				return nil, protocolError("audit_write_failed", "Wardkey could not record the credential decision")
			}
			return nil, protocolError(
				"approval_required",
				"this request requires an approval flow that is not configured",
			)
		}

		approved, approvalErr := provider.Approve(ctx, CredentialApprovalRequest{
			RequestID: request.ID,
			Operation: request.Op,
			Provider:  args.Provider,
			Profile:   args.Profile,
			Caller:    caller,
		})
		if approvalErr != nil {
			if err := h.appendCredentialAudit(caller, args, "approval_error"); err != nil {
				return nil, protocolError("audit_write_failed", "Wardkey could not record the approval result")
			}
			return nil, protocolError("approval_failed", "Wardkey could not complete the approval request")
		}
		if err := ctx.Err(); err != nil {
			if auditErr := h.appendCredentialAudit(caller, args, "cancelled"); auditErr != nil {
				return nil, protocolError("audit_write_failed", "Wardkey could not record the cancelled request")
			}
			return nil, protocolError("request_cancelled", "request was cancelled")
		}
		if !approved {
			if err := h.appendCredentialAudit(caller, args, "approval_denied"); err != nil {
				return nil, protocolError("audit_write_failed", "Wardkey could not record the approval decision")
			}
			return nil, protocolError("approval_denied", "credential request was not approved")
		}
		if err := h.appendCredentialAudit(caller, args, "approval_granted"); err != nil {
			return nil, protocolError("audit_write_failed", "Wardkey could not record the approval decision")
		}

	case policy.DecisionAllow:
		// Continue below.

	default:
		if err := h.appendCredentialAudit(caller, args, "invalid_decision"); err != nil {
			return nil, protocolError("audit_write_failed", "Wardkey could not record the credential decision")
		}
		return nil, protocolError("policy_denied", "policy returned an invalid decision")
	}

	if h.executor == nil {
		if err := h.appendCredentialAudit(caller, args, "unavailable"); err != nil {
			return nil, protocolError("audit_write_failed", "Wardkey could not record the credential decision")
		}
		return nil, protocolError(
			"operation_unavailable",
			"credential retrieval is not implemented yet",
		)
	}

	var data json.RawMessage
	var executorErr *ipc.ProtocolError
	err = h.session.WithCredential(args.Provider, args.Profile, func(value []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, executorErr = h.executor(ctx, caller, request, value)
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrSessionLocked):
			if auditErr := h.appendCredentialAudit(caller, args, "vault_locked"); auditErr != nil {
				return nil, protocolError("audit_write_failed", "Wardkey could not record the locked credential request")
			}
			return nil, protocolError("vault_locked", "the vault is locked")

		case errors.Is(err, ErrCredentialNotFound):
			if auditErr := h.appendCredentialAudit(caller, args, "not_found"); auditErr != nil {
				return nil, protocolError("audit_write_failed", "Wardkey could not record the credential decision")
			}
			return nil, protocolError("credential_not_found", "no matching credential exists")

		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			if auditErr := h.appendCredentialAudit(caller, args, "cancelled"); auditErr != nil {
				return nil, protocolError("audit_write_failed", "Wardkey could not record the credential decision")
			}
			return nil, protocolError("request_cancelled", "request was cancelled")

		default:
			if auditErr := h.appendCredentialAudit(caller, args, "failed"); auditErr != nil {
				return nil, protocolError("audit_write_failed", "Wardkey could not record the credential decision")
			}
			return nil, protocolError("internal_error", "Wardkey could not access the requested credential")
		}
	}

	if executorErr != nil {
		clear(data)
		if err := h.appendCredentialAudit(caller, args, "executor_error"); err != nil {
			return nil, protocolError("audit_write_failed", "Wardkey could not record the credential decision")
		}
		return nil, executorErr
	}
	if len(data) > 0 && !json.Valid(data) {
		clear(data)
		if err := h.appendCredentialAudit(caller, args, "executor_error"); err != nil {
			return nil, protocolError("audit_write_failed", "Wardkey could not record the credential decision")
		}
		return nil, protocolError("internal_error", "credential executor returned invalid data")
	}

	return h.returnCredentialAfterAudit(caller, args, data)
}

func isWardkeyGitHelper(imagePath string) bool {
	name := imagePath
	if index := strings.LastIndexAny(name, `/\`); index >= 0 {
		name = name[index+1:]
	}
	return strings.EqualFold(name, "git-credential-wardkey.exe")
}

func isGitExecutable(imagePath string) bool {
	name := imagePath
	if index := strings.LastIndexAny(name, `/\`); index >= 0 {
		name = name[index+1:]
	}
	return strings.EqualFold(name, "git.exe")
}

func isWardkeyExecutable(imagePath string) bool {
	name := imagePath
	if index := strings.LastIndexAny(name, `/\`); index >= 0 {
		name = name[index+1:]
	}
	return strings.EqualFold(name, "wardkey.exe")
}

func isAWSCLIExecutable(imagePath string) bool {
	name := imagePath
	if index := strings.LastIndexAny(name, `/\`); index >= 0 {
		name = name[index+1:]
	}
	return strings.EqualFold(name, "aws.exe")
}

type credentialArgs struct {
	Provider string `json:"provider"`
	Profile  string `json:"profile,omitempty"`
}

func decodeCredentialArgs(raw json.RawMessage) (credentialArgs, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return credentialArgs{}, errors.New("credential request arguments are required")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var args credentialArgs
	if err := decoder.Decode(&args); err != nil {
		return credentialArgs{}, fmt.Errorf("decode credential arguments: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return credentialArgs{}, errors.New("credential arguments contain trailing data")
	}

	args.Provider = strings.TrimSpace(args.Provider)
	args.Profile = strings.TrimSpace(args.Profile)

	if args.Provider == "" || len(args.Provider) > 128 {
		return credentialArgs{}, errors.New("provider is missing or too long")
	}
	if args.Profile == "" || len(args.Profile) > 128 {
		return credentialArgs{}, errors.New("profile is missing or too long")
	}

	return args, nil
}

func successData(value any) (json.RawMessage, *ipc.ProtocolError) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, protocolError("internal_error", "Wardkey could not encode its response")
	}
	return json.RawMessage(data), nil
}

func protocolError(code, message string) *ipc.ProtocolError {
	return &ipc.ProtocolError{
		Code:    code,
		Message: message,
	}
}

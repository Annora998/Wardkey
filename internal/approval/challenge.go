package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"wardkey/internal/identity"
	"wardkey/internal/ipc"
)

const requestChallengeDomain = "wardkey/webauthn/request-approval/v1\x00"

// Request contains the trusted fields that must be bound to one approval.
// Caller identity must come from the broker's platform inspection.
type Request struct {
	RequestID string
	Operation ipc.Operation
	Provider  string
	Profile   string
	Caller    identity.ProcessIdentity
	RPID      string
}

type requestChallengeBinding struct {
	Version             int           `json:"version"`
	RequestID           string        `json:"request_id"`
	Operation           ipc.Operation `json:"operation"`
	Provider            string        `json:"provider"`
	Profile             string        `json:"profile"`
	RPID                string        `json:"rp_id"`
	CallerPID           uint32        `json:"caller_pid"`
	CallerImagePath     string        `json:"caller_image_path"`
	CallerImageFileHash string        `json:"caller_image_file_sha256"`
	CallerCreationTime  uint64        `json:"caller_process_creation_time"`
}

// NewRequestChallenge returns a fresh 32-byte challenge bound to the complete
// request and inspected caller. The caller must clear the returned bytes.
func NewRequestChallenge(request Request) ([]byte, error) {
	return newRequestChallenge(request, rand.Reader)
}

func newRequestChallenge(request Request, nonceSource io.Reader) ([]byte, error) {
	if nonceSource == nil {
		return nil, errors.New("approval challenge nonce source is unavailable")
	}
	if strings.TrimSpace(request.Provider) == "" || len(request.Provider) > 128 {
		return nil, errors.New("approval request provider is invalid")
	}
	if strings.TrimSpace(request.Profile) == "" || len(request.Profile) > 128 {
		return nil, errors.New("approval request profile is invalid")
	}
	if strings.TrimSpace(request.RPID) == "" || request.RPID != strings.TrimSpace(request.RPID) {
		return nil, errors.New("approval relying-party ID is invalid")
	}
	if err := request.Caller.Validate(); err != nil {
		return nil, fmt.Errorf("approval caller identity is invalid: %w", err)
	}

	envelope := ipc.Request{
		Version: ipc.ProtocolVersion,
		ID:      request.RequestID,
		Op:      request.Operation,
	}
	if err := envelope.Validate(); err != nil {
		return nil, fmt.Errorf("approval request envelope is invalid: %w", err)
	}
	if request.Operation != ipc.OpGetCred && request.Operation != ipc.OpGetGitCred {
		return nil, errors.New("operation cannot be approved for credential release")
	}

	binding := requestChallengeBinding{
		Version:             1,
		RequestID:           request.RequestID,
		Operation:           request.Operation,
		Provider:            request.Provider,
		Profile:             request.Profile,
		RPID:                request.RPID,
		CallerPID:           request.Caller.PID,
		CallerImagePath:     request.Caller.ImagePath,
		CallerImageFileHash: hex.EncodeToString(request.Caller.ImageFileSHA256[:]),
		CallerCreationTime:  request.Caller.ProcessCreationTime,
	}

	bindingJSON, err := json.Marshal(binding)
	if err != nil {
		return nil, fmt.Errorf("encode approval request binding: %w", err)
	}
	defer clear(bindingJSON)

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(nonceSource, nonce); err != nil {
		clear(nonce)
		return nil, fmt.Errorf("generate approval challenge nonce: %w", err)
	}
	defer clear(nonce)

	hash := sha256.New()
	_, _ = hash.Write([]byte(requestChallengeDomain))
	_, _ = hash.Write(bindingJSON)
	_, _ = hash.Write(nonce)

	return hash.Sum(nil), nil
}

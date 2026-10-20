package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"wardkey/internal/identity"
	"wardkey/internal/ipc"
)

const maxAWSStoredCredentialSize = 16 << 10

type awsStoredCredential struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
	Expiration      string `json:"expiration,omitempty"`
}

type awsCredentialProcessResponse struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}

// AWSCredentialProcessExecutor returns an AWS credential_process response.
// The handler has already checked the caller identity and policy.
func AWSCredentialProcessExecutor(
	ctx context.Context,
	caller identity.ProcessIdentity,
	request ipc.Request,
	credential []byte,
) (json.RawMessage, *ipc.ProtocolError) {
	if ctx == nil || ctx.Err() != nil {
		return nil, protocolError("request_cancelled", "request was cancelled")
	}
	if request.Op != ipc.OpGetCred || request.Validate() != nil {
		return nil, protocolError("invalid_request", "AWS credential request is invalid")
	}
	if caller.Validate() != nil {
		return nil, protocolError("invalid_caller", "Wardkey could not verify the caller process")
	}
	if len(credential) == 0 || len(credential) > maxAWSStoredCredentialSize {
		return nil, protocolError("credential_unavailable", "the stored AWS credential is invalid")
	}

	args, err := decodeCredentialArgs(request.Args)
	if err != nil || args.Provider != "aws" {
		return nil, protocolError("invalid_arguments", "AWS credential request arguments are invalid")
	}

	decoder := json.NewDecoder(bytes.NewReader(credential))
	decoder.DisallowUnknownFields()

	var stored awsStoredCredential
	if err := decoder.Decode(&stored); err != nil {
		return nil, protocolError("credential_unavailable", "the stored AWS credential is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, protocolError("credential_unavailable", "the stored AWS credential is invalid")
	}

	if !validGitCredentialText(stored.AccessKeyID) ||
		!validGitCredentialText(stored.SecretAccessKey) ||
		(stored.SessionToken != "" && !validGitCredentialText(stored.SessionToken)) {
		return nil, protocolError("credential_unavailable", "the stored AWS credential is invalid")
	}
	if stored.Expiration != "" {
		expiration, err := time.Parse(time.RFC3339, stored.Expiration)
		if err != nil || !expiration.After(time.Now()) {
			return nil, protocolError("credential_unavailable", "the stored AWS credential is expired or invalid")
		}
	}

	response, err := json.Marshal(awsCredentialProcessResponse{
		Version:         1,
		AccessKeyID:     stored.AccessKeyID,
		SecretAccessKey: stored.SecretAccessKey,
		SessionToken:    stored.SessionToken,
		Expiration:      stored.Expiration,
	})
	if err != nil {
		return nil, protocolError("internal_error", "Wardkey could not encode the AWS credential response")
	}

	return json.RawMessage(response), nil
}

// CredentialExecutor dispatches authorized credential requests to their
// operation-specific response formatters.
func CredentialExecutor(
	ctx context.Context,
	caller identity.ProcessIdentity,
	request ipc.Request,
	credential []byte,
) (json.RawMessage, *ipc.ProtocolError) {
	switch request.Op {
	case ipc.OpGetGitCred:
		return GitCredentialExecutor(ctx, caller, request, credential)
	case ipc.OpGetCred:
		return AWSCredentialProcessExecutor(ctx, caller, request, credential)
	default:
		return nil, protocolError("unsupported_operation", "credential operation is not supported")
	}
}

var _ OperationExecutor = AWSCredentialProcessExecutor
var _ OperationExecutor = CredentialExecutor

var _ = errors.New

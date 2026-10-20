package broker

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"wardkey/internal/identity"
	"wardkey/internal/ipc"
)

func TestAWSCredentialProcessExecutorReturnsCredentialProcessJSON(t *testing.T) {
	request := awsExecutorTestRequest(t, ipc.OpGetCred, "aws")
	credential := []byte(`{
		"access_key_id": "dummy-access-key",
		"secret_access_key": "dummy-secret-key",
		"session_token": "dummy-session-token",
		"expiration": "2099-01-01T00:00:00Z"
	}`)

	data, protocolErr := AWSCredentialProcessExecutor(
		context.Background(),
		awsExecutorTestCaller(t),
		request,
		credential,
	)
	if protocolErr != nil {
		t.Fatalf("AWSCredentialProcessExecutor() error = %v", protocolErr)
	}

	var got struct {
		Version         int    `json:"Version"`
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken"`
		Expiration      string `json:"Expiration"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode AWS credential process response: %v", err)
	}

	if got.Version != 1 {
		t.Errorf("Version = %d, want 1", got.Version)
	}
	if got.AccessKeyID != "dummy-access-key" {
		t.Errorf("AccessKeyId = %q, want the dummy access key", got.AccessKeyID)
	}
	if got.SecretAccessKey != "dummy-secret-key" {
		t.Errorf("SecretAccessKey = %q, want the dummy secret key", got.SecretAccessKey)
	}
	if got.SessionToken != "dummy-session-token" {
		t.Errorf("SessionToken = %q, want the dummy session token", got.SessionToken)
	}
	if got.Expiration != "2099-01-01T00:00:00Z" {
		t.Errorf("Expiration = %q, want the supplied expiration", got.Expiration)
	}
}

func TestAWSCredentialProcessExecutorRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name       string
		op         ipc.Operation
		provider   string
		credential string
	}{
		{
			name:     "wrong operation",
			op:       ipc.OpGetGitCred,
			provider: "aws",
			credential: `{
				"access_key_id": "dummy-access-key",
				"secret_access_key": "dummy-secret-key"
			}`,
		},
		{
			name:     "wrong provider",
			op:       ipc.OpGetCred,
			provider: "generic",
			credential: `{
				"access_key_id": "dummy-access-key",
				"secret_access_key": "dummy-secret-key"
			}`,
		},
		{
			name:       "invalid JSON",
			op:         ipc.OpGetCred,
			provider:   "aws",
			credential: `not-json`,
		},
		{
			name:     "missing secret key",
			op:       ipc.OpGetCred,
			provider: "aws",
			credential: `{
				"access_key_id": "dummy-access-key"
			}`,
		},
		{
			name:     "expired credential",
			op:       ipc.OpGetCred,
			provider: "aws",
			credential: `{
				"access_key_id": "dummy-access-key",
				"secret_access_key": "dummy-secret-key",
				"expiration": "2000-01-01T00:00:00Z"
			}`,
		},
		{
			name:     "unknown field",
			op:       ipc.OpGetCred,
			provider: "aws",
			credential: `{
				"access_key_id": "dummy-access-key",
				"secret_access_key": "dummy-secret-key",
				"unexpected": "value"
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := awsExecutorTestRequest(t, tt.op, tt.provider)

			data, protocolErr := AWSCredentialProcessExecutor(
				context.Background(),
				awsExecutorTestCaller(t),
				request,
				[]byte(tt.credential),
			)
			if protocolErr == nil {
				t.Fatal("AWSCredentialProcessExecutor() returned no error")
			}
			if data != nil {
				t.Fatal("AWSCredentialProcessExecutor() returned data for an invalid request")
			}
		})
	}
}

func TestAWSCredentialProcessExecutorRejectsCancelledRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	request := awsExecutorTestRequest(t, ipc.OpGetCred, "aws")
	credential := []byte(`{
		"access_key_id": "dummy-access-key",
		"secret_access_key": "dummy-secret-key"
	}`)

	data, protocolErr := AWSCredentialProcessExecutor(
		ctx,
		awsExecutorTestCaller(t),
		request,
		credential,
	)
	if protocolErr == nil || protocolErr.Code != "request_cancelled" {
		t.Fatalf("error = %v, want request_cancelled", protocolErr)
	}
	if data != nil {
		t.Fatal("AWSCredentialProcessExecutor() returned data for a cancelled request")
	}
}

func awsExecutorTestRequest(
	t *testing.T,
	op ipc.Operation,
	provider string,
) ipc.Request {
	t.Helper()

	args, err := json.Marshal(credentialArgs{
		Provider: provider,
		Profile:  "dummy-profile",
	})
	if err != nil {
		t.Fatalf("marshal request arguments: %v", err)
	}

	return ipc.Request{
		Version: ipc.ProtocolVersion,
		ID:      "aws-test-request",
		Op:      op,
		Args:    args,
	}
}

func awsExecutorTestCaller(t *testing.T) identity.ProcessIdentity {
	t.Helper()

	var hash [32]byte
	hash[0] = 1

	return identity.ProcessIdentity{
		PID:                 1234,
		ImagePath:           filepath.Join(t.TempDir(), "aws.exe"),
		ImageFileSHA256:     hash,
		ProcessCreationTime: uint64(time.Now().UnixNano()),
	}
}

package broker

import (
	"context"
	"encoding/json"
	"testing"

	"wardkey/internal/identity"
	"wardkey/internal/ipc"
)

func TestGitCredentialExecutorReturnsCredentialForValidRequest(t *testing.T) {
	request := gitExecutorTestRequest(t, ipc.OpGetGitCred, "github", "github.com/owner/repo/alice")
	caller := gitExecutorTestCaller()

	data, protocolErr := GitCredentialExecutor(
		context.Background(),
		caller,
		request,
		[]byte("dummy-token"),
	)
	if protocolErr != nil {
		t.Fatalf("GitCredentialExecutor() error = %v", protocolErr)
	}

	var got gitCredentialResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode executor response: %v", err)
	}
	if got.Username != "alice" {
		t.Errorf("Username = %q, want alice", got.Username)
	}
	if string(got.Password) != "dummy-token" {
		t.Errorf("Password did not match the dummy test value")
	}
	clear(got.Password)
	clear(data)
}

func TestGitCredentialExecutorRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name     string
		op       ipc.Operation
		provider string
		profile  string
		secret   []byte
	}{
		{
			name:     "wrong operation",
			op:       ipc.OpGetCred,
			provider: "github",
			profile:  "github.com/owner/repo/alice",
			secret:   []byte("dummy-token"),
		},
		{
			name:     "provider does not match GitHub host",
			op:       ipc.OpGetGitCred,
			provider: "generic",
			profile:  "github.com/owner/repo/alice",
			secret:   []byte("dummy-token"),
		},
		{
			name:     "profile has no username",
			op:       ipc.OpGetGitCred,
			provider: "github",
			profile:  "github.com/owner/repo/",
			secret:   []byte("dummy-token"),
		},
		{
			name:     "profile contains traversal",
			op:       ipc.OpGetGitCred,
			provider: "github",
			profile:  "github.com/owner/../repo/alice",
			secret:   []byte("dummy-token"),
		},
		{
			name:     "empty credential",
			op:       ipc.OpGetGitCred,
			provider: "github",
			profile:  "github.com/owner/repo/alice",
			secret:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := gitExecutorTestRequest(t, tt.op, tt.provider, tt.profile)

			data, protocolErr := GitCredentialExecutor(
				context.Background(),
				gitExecutorTestCaller(),
				request,
				tt.secret,
			)
			if protocolErr == nil {
				clear(data)
				t.Fatal("GitCredentialExecutor() error = nil, want rejection")
			}
			if len(data) != 0 {
				clear(data)
				t.Fatal("GitCredentialExecutor() returned data for a rejected request")
			}
		})
	}
}

func TestGitCredentialExecutorRejectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	request := gitExecutorTestRequest(t, ipc.OpGetGitCred, "github", "github.com/owner/repo/alice")
	data, protocolErr := GitCredentialExecutor(
		ctx,
		gitExecutorTestCaller(),
		request,
		[]byte("dummy-token"),
	)
	if protocolErr == nil {
		clear(data)
		t.Fatal("GitCredentialExecutor() error = nil, want cancellation error")
	}
	if len(data) != 0 {
		clear(data)
		t.Fatal("GitCredentialExecutor() returned data for a cancelled request")
	}
}

func gitExecutorTestRequest(
	t *testing.T,
	op ipc.Operation,
	provider string,
	profile string,
) ipc.Request {
	t.Helper()

	args, err := json.Marshal(credentialArgs{
		Provider: provider,
		Profile:  profile,
	})
	if err != nil {
		t.Fatalf("encode test request arguments: %v", err)
	}

	return ipc.Request{
		Version: ipc.ProtocolVersion,
		ID:      "test-request-1",
		Op:      op,
		Args:    args,
	}
}

func gitExecutorTestCaller() identity.ProcessIdentity {
	var hash [32]byte
	hash[0] = 1

	return identity.ProcessIdentity{
		PID:                 1234,
		ImagePath:           `C:\Program Files\Git\bin\git.exe`,
		ImageFileSHA256:     hash,
		ProcessCreationTime: 1,
	}
}

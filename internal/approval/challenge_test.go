package approval

import (
	"bytes"
	"path/filepath"
	"testing"

	"wardkey/internal/identity"
	"wardkey/internal/ipc"
)

func TestRequestChallengeBindsEveryRequestField(t *testing.T) {
	imagePath, err := filepath.Abs("git.exe")
	if err != nil {
		t.Fatalf("resolve test image path: %v", err)
	}

	var imageHash [32]byte
	imageHash[0] = 1

	base := Request{
		RequestID: "0123456789abcdef0123456789abcdef",
		Operation: ipc.OpGetGitCred,
		Provider:  "generic",
		Profile:   "wardkey-test.invalid/owner/repo/probe",
		Caller: identity.ProcessIdentity{
			PID:                 1234,
			ImagePath:           imagePath,
			ImageFileSHA256:     imageHash,
			ProcessCreationTime: 1,
		},
		RPID: RPID,
	}

	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{"request ID", func(r *Request) { r.RequestID = "fedcba9876543210fedcba9876543210" }},
		{"operation", func(r *Request) { r.Operation = ipc.OpGetCred }},
		{"provider", func(r *Request) { r.Provider = "other" }},
		{"profile", func(r *Request) { r.Profile = "other-profile" }},
		{"relying party", func(r *Request) { r.RPID = "other.local" }},
		{"caller PID", func(r *Request) { r.Caller.PID++ }},
		{"caller image path", func(r *Request) { r.Caller.ImagePath = filepath.Join(filepath.Dir(imagePath), "other.exe") }},
		{"caller image hash", func(r *Request) { r.Caller.ImageFileSHA256[0]++ }},
		{"caller creation time", func(r *Request) { r.Caller.ProcessCreationTime++ }},
	}

	fixedNonce := bytes.Repeat([]byte{0xA5}, 32)
	baseChallenge := challengeWithFixedNonce(t, base, fixedNonce)
	defer clear(baseChallenge)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)

			changedChallenge := challengeWithFixedNonce(t, changed, fixedNonce)
			defer clear(changedChallenge)

			if bytes.Equal(changedChallenge, baseChallenge) {
				t.Fatal("changing this request field did not change the challenge")
			}
		})
	}
}

func TestRequestChallengeRejectsShortNonceSource(t *testing.T) {
	imagePath, err := filepath.Abs("git.exe")
	if err != nil {
		t.Fatalf("resolve test image path: %v", err)
	}

	var imageHash [32]byte
	imageHash[0] = 1

	request := Request{
		RequestID: "0123456789abcdef0123456789abcdef",
		Operation: ipc.OpGetGitCred,
		Provider:  "generic",
		Profile:   "wardkey-test.invalid/owner/repo/probe",
		Caller: identity.ProcessIdentity{
			PID:                 1234,
			ImagePath:           imagePath,
			ImageFileSHA256:     imageHash,
			ProcessCreationTime: 1,
		},
		RPID: RPID,
	}

	if _, err := newRequestChallenge(request, bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("newRequestChallenge() accepted a short nonce source")
	}
}

func challengeWithFixedNonce(t *testing.T, request Request, nonce []byte) []byte {
	t.Helper()

	challenge, err := newRequestChallenge(request, bytes.NewReader(nonce))
	if err != nil {
		t.Fatalf("newRequestChallenge() error = %v", err)
	}
	return challenge
}

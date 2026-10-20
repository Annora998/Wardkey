//go:build windows

package approval

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"wardkey/internal/identity"
	"wardkey/internal/ipc"
)

func TestVerifyAssertionRejectsReplayedChallenge(t *testing.T) {
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

	previousChallenge, err := NewRequestChallenge(request)
	if err != nil {
		t.Fatalf("create previous challenge: %v", err)
	}
	defer clear(previousChallenge)

	currentChallenge, err := NewRequestChallenge(request)
	if err != nil {
		t.Fatalf("create current challenge: %v", err)
	}
	defer clear(currentChallenge)

	if equalBytes(previousChallenge, currentChallenge) {
		t.Fatal("separate requests reused the same challenge")
	}

	credentialID := []byte{0x42}
	authenticatorData := make([]byte, 37)
	rpIDHash := sha256.Sum256([]byte(RPID))
	copy(authenticatorData[:32], rpIDHash[:])
	authenticatorData[32] = 0x05 // user present and user verified

	signature := []byte{0x01}
	clientJSON, err := json.Marshal(clientDataJSON{
		Type:      "webauthn.get",
		Challenge: base64.RawURLEncoding.EncodeToString(previousChallenge),
		Origin:    "https://" + RPID,
	})
	if err != nil {
		t.Fatalf("encode test client data: %v", err)
	}
	defer clear(clientJSON)

	assertion := webAuthnAssertion{
		authenticatorDataLength: uint32(len(authenticatorData)),
		authenticatorData:       unsafe.Pointer(&authenticatorData[0]),
		signatureLength:         uint32(len(signature)),
		signature:               unsafe.Pointer(&signature[0]),
		credential: webAuthnCredential{
			idLength: uint32(len(credentialID)),
			id:       unsafe.Pointer(&credentialID[0]),
		},
	}

	enrollment := Enrollment{
		RPID:         RPID,
		CredentialID: credentialID,
	}

	err = verifyAssertion(&assertion, enrollment, clientJSON, currentChallenge)
	if err == nil || !strings.Contains(err.Error(), "assertion challenge does not match this request") {
		t.Fatalf("verifyAssertion() error = %v, want replayed-challenge rejection", err)
	}
}

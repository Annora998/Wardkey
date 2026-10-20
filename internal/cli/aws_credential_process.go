package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"wardkey/internal/ipc"
)

type awsCredentialRequest struct {
	Provider string `json:"provider"`
	Profile  string `json:"profile"`
}

type awsCredentialProcessResponse struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}

// ExecuteAWSCredentialProcess gets one AWS profile's credentials from the
// broker and writes the JSON format expected by AWS CLI credential_process.
func ExecuteAWSCredentialProcess(args []string, output io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: wardkey aws-credential-process <profile>")
	}
	if output == nil {
		return errors.New("AWS credential output is unavailable")
	}

	profile := strings.TrimSpace(args[0])
	if !validGitText(profile) || len(profile) > 128 {
		return errors.New("AWS credential profile is invalid")
	}

	connection, err := ipc.DialCurrentUserPipe()
	if err != nil {
		return fmt.Errorf("connect to Wardkey broker: %w", err)
	}
	defer connection.Close()

	deadline := time.Now().Add(30 * time.Second)
	if err := connection.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("set broker read deadline: %w", err)
	}
	if err := connection.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set broker write deadline: %w", err)
	}

	var requestID [16]byte
	if _, err := rand.Read(requestID[:]); err != nil {
		return fmt.Errorf("create broker request ID: %w", err)
	}

	requestArgs, err := json.Marshal(awsCredentialRequest{
		Provider: "aws",
		Profile:  profile,
	})
	if err != nil {
		return fmt.Errorf("encode AWS credential request: %w", err)
	}
	defer clear(requestArgs)

	request := ipc.Request{
		Version: ipc.ProtocolVersion,
		ID:      hex.EncodeToString(requestID[:]),
		Op:      ipc.OpGetCred,
		Args:    requestArgs,
	}

	var credentials awsCredentialProcessResponse
	if err := ipc.RoundTrip(connection, request, &credentials); err != nil {
		return fmt.Errorf("request AWS credentials from Wardkey: %w", err)
	}

	if credentials.Version != 1 ||
		credentials.AccessKeyID == "" ||
		credentials.SecretAccessKey == "" {
		return errors.New("broker returned an incomplete AWS credential response")
	}
	if credentials.Expiration != "" {
		expiration, err := time.Parse(time.RFC3339, credentials.Expiration)
		if err != nil || !expiration.After(time.Now()) {
			return errors.New("broker returned an invalid or expired AWS credential")
		}
	}

	response, err := json.Marshal(credentials)
	if err != nil {
		return errors.New("encode AWS credential response")
	}
	defer clear(response)

	if _, err := output.Write(append(response, '\n')); err != nil {
		return errors.New("write AWS credential response")
	}
	return nil
}

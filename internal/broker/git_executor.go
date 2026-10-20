package broker

import (
	"context"
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"

	"wardkey/internal/identity"
	"wardkey/internal/ipc"
)

type gitCredentialResponse struct {
	Username string `json:"username"`
	Password []byte `json:"password"`
}

// GitCredentialExecutor returns a credential only for a validated Git helper
// request. Handler has already checked the caller identity and policy.
func GitCredentialExecutor(
	ctx context.Context,
	caller identity.ProcessIdentity,
	request ipc.Request,
	credential []byte,
) (json.RawMessage, *ipc.ProtocolError) {
	if ctx == nil || ctx.Err() != nil {
		return nil, protocolError("request_cancelled", "request was cancelled")
	}
	if request.Op != ipc.OpGetGitCred || request.Validate() != nil {
		return nil, protocolError("invalid_request", "Git credential request is invalid")
	}
	if caller.Validate() != nil {
		return nil, protocolError("invalid_caller", "Wardkey could not verify the caller process")
	}
	if !validGitCredentialBytes(credential) {
		return nil, protocolError("credential_unavailable", "the stored credential cannot be returned to Git")
	}

	args, err := decodeCredentialArgs(request.Args)
	if err != nil || (args.Provider != "github" && args.Provider != "generic") {
		return nil, protocolError("invalid_arguments", "Git credential request arguments are invalid")
	}

	host, username, ok := gitPartsFromProfile(args.Profile)
	if !ok ||
		(args.Provider == "github" && host != "github.com") ||
		(args.Provider == "generic" && host == "github.com") {
		return nil, protocolError("invalid_arguments", "Git credential profile is invalid")
	}

	data, err := json.Marshal(gitCredentialResponse{
		Username: username,
		Password: credential,
	})
	if err != nil {
		return nil, protocolError("internal_error", "Wardkey could not encode the credential response")
	}
	return json.RawMessage(data), nil
}

func gitPartsFromProfile(profile string) (host, username string, ok bool) {
	lastSlash := strings.LastIndexByte(profile, '/')
	firstSlash := strings.IndexByte(profile, '/')
	if firstSlash <= 0 || lastSlash <= firstSlash+1 || lastSlash == len(profile)-1 {
		return "", "", false
	}

	host = profile[:firstSlash]
	repositoryPath := profile[firstSlash+1 : lastSlash]
	username = profile[lastSlash+1:]

	if !validGitCredentialText(host) ||
		strings.ContainsAny(host, "/\\?#@ \t\r\n") {
		return "", "", false
	}
	if !validGitCredentialText(username) ||
		strings.ContainsAny(username, `/\`) {
		return "", "", false
	}
	if !validGitCredentialText(repositoryPath) ||
		strings.HasPrefix(repositoryPath, "/") ||
		strings.HasSuffix(repositoryPath, "/") ||
		strings.ContainsAny(repositoryPath, `\?#`) {
		return "", "", false
	}
	for _, segment := range strings.Split(repositoryPath, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", "", false
		}
	}
	return host, username, true
}

func validGitCredentialBytes(value []byte) bool {
	if len(value) == 0 || !utf8.Valid(value) {
		return false
	}
	for len(value) > 0 {
		char, size := utf8.DecodeRune(value)
		if unicode.IsControl(char) {
			return false
		}
		value = value[size:]
	}
	return true
}

func validGitCredentialText(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

// Keep this compile-time check so changes to the executor signature are caught.
var _ OperationExecutor = GitCredentialExecutor

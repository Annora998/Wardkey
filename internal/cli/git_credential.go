package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"wardkey/internal/ipc"
)

const maxGitCredentialInput = 64 << 10

type gitCredentialRequest struct {
	Provider string `json:"provider"`
	Profile  string `json:"profile"`
}

type gitCredentialResponse struct {
	Username string `json:"username"`
	Password []byte `json:"password"`
}

type gitCredentialInput struct {
	Protocol string
	Host     string
	Path     string
	Username string
}

// ExecuteGitCredentialHelper handles Git's get, store, and erase helper actions.
func ExecuteGitCredentialHelper(args []string, input io.Reader, output io.Writer) error {
	if len(args) != 1 {
		return errors.New("expected one Git credential helper action")
	}

	switch args[0] {
	case "store", "erase":
		// Wardkey's encrypted vault is authoritative; Git must not store or
		// erase credentials through this helper.
		return nil
	case "get":
		// Continue below.
	default:
		return errors.New("unsupported Git credential helper action")
	}

	requestInput, err := parseGitCredentialInput(input)
	if err != nil {
		return err
	}

	profile := requestInput.Host + "/" + requestInput.Path + "/" + requestInput.Username
	if len(profile) > 128 {
		return errors.New("Git host, repository path, and username exceed Wardkey's profile limit")
	}

	provider := "generic"
	if requestInput.Host == "github.com" {
		provider = "github"
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

	requestArgs, err := json.Marshal(gitCredentialRequest{
		Provider: provider,
		Profile:  profile,
	})
	if err != nil {
		return fmt.Errorf("encode Git credential request: %w", err)
	}
	defer clear(requestArgs)

	request := ipc.Request{
		Version: ipc.ProtocolVersion,
		ID:      hex.EncodeToString(requestID[:]),
		Op:      ipc.OpGetGitCred,
		Args:    requestArgs,
	}

	var credential gitCredentialResponse
	defer clear(credential.Password)

	if err := ipc.RoundTrip(connection, request, &credential); err != nil {
		return fmt.Errorf("request Git credential from Wardkey: %w", err)
	}
	if credential.Username != requestInput.Username {
		return errors.New("broker returned a credential for a different username")
	}
	if !validGitField(credential.Password) {
		return errors.New("broker returned a credential that Git cannot safely accept")
	}

	if err := writeGitCredential(output, credential.Username, credential.Password); err != nil {
		return fmt.Errorf("write Git credential response: %w", err)
	}
	return nil
}

func parseGitCredentialInput(input io.Reader) (gitCredentialInput, error) {
	if input == nil {
		return gitCredentialInput{}, errors.New("Git credential input is unavailable")
	}

	raw, err := io.ReadAll(io.LimitReader(input, maxGitCredentialInput+1))
	if err != nil {
		return gitCredentialInput{}, errors.New("read Git credential request")
	}
	defer clear(raw)

	if len(raw) > maxGitCredentialInput {
		return gitCredentialInput{}, errors.New("Git credential request is too large")
	}

	fields := make(map[string]string, 4)
	for start := 0; start < len(raw); {
		end := bytes.IndexByte(raw[start:], '\n')
		var line []byte
		if end < 0 {
			line = raw[start:]
			start = len(raw)
		} else {
			line = raw[start : start+end]
			start += end + 1
		}
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 {
			break
		}

		separator := bytes.IndexByte(line, '=')
		if separator <= 0 {
			return gitCredentialInput{}, errors.New("Git credential request contains an invalid field")
		}

		key := string(line[:separator])
		switch key {
		case "protocol", "host", "path", "username":
			if _, exists := fields[key]; exists {
				return gitCredentialInput{}, errors.New("Git credential request contains a duplicate field")
			}
			fields[key] = string(line[separator+1:])
		default:
			// Ignore fields such as password. The request parser never copies
			// their values into Go strings.
		}
	}

	if fields["protocol"] != "https" {
		return gitCredentialInput{}, errors.New("Wardkey Git credentials require HTTPS")
	}

	host, err := normalizeGitHost(fields["host"])
	if err != nil {
		return gitCredentialInput{}, err
	}

	path := fields["path"]
	if err := validateGitPath(path); err != nil {
		return gitCredentialInput{}, err
	}

	username := fields["username"]
	if !validGitText(username) || strings.ContainsAny(username, `/\`) {
		return gitCredentialInput{}, errors.New("Git must provide a valid username")
	}

	return gitCredentialInput{
		Protocol: "https",
		Host:     host,
		Path:     path,
		Username: username,
	}, nil
}

func normalizeGitHost(host string) (string, error) {
	if host == "" || len(host) > 255 || strings.ContainsAny(host, "/\\?#@ \t\r\n") {
		return "", errors.New("Git credential request has an invalid host")
	}

	name := host
	port := ""
	if strings.Count(host, ":") > 1 {
		return "", errors.New("IPv6 Git hosts are not supported by this helper yet")
	}
	if separator := strings.LastIndexByte(host, ':'); separator >= 0 {
		name = host[:separator]
		port = host[separator+1:]
		portNumber, err := strconv.Atoi(port)
		if name == "" || err != nil || portNumber < 1 || portNumber > 65535 {
			return "", errors.New("Git credential request has an invalid host port")
		}
		port = strconv.Itoa(portNumber)
	}

	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if !validGitHostName(name) {
		return "", errors.New("Git credential request has an invalid host")
	}
	if port != "" {
		return name + ":" + port, nil
	}
	return name, nil
}

func validGitHostName(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') ||
				(char >= '0' && char <= '9') ||
				char == '-') {
				return false
			}
		}
	}
	return true
}

func validateGitPath(path string) error {
	if !validGitText(path) || strings.ContainsAny(path, `\?#`) {
		return errors.New("Git must provide a valid repository path")
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return errors.New("Git repository path must be relative")
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("Git repository path contains an invalid segment")
		}
	}
	return nil
}

func validGitText(value string) bool {
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

func validGitField(value []byte) bool {
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

func writeGitCredential(output io.Writer, username string, password []byte) error {
	if output == nil {
		return errors.New("Git credential output is unavailable")
	}
	if err := writeGitBytes(output, []byte("username="+username+"\npassword=")); err != nil {
		return err
	}
	if err := writeGitBytes(output, password); err != nil {
		return err
	}
	return writeGitBytes(output, []byte("\n\n"))
}

func writeGitBytes(output io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := output.Write(value)
		if written < 0 || written > len(value) {
			return errors.New("invalid output write count")
		}
		value = value[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

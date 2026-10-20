package ipc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

const ProtocolVersion uint16 = 1

type Operation string

const (
	OpHello      Operation = "hello"
	OpGetCred    Operation = "get_cred"
	OpGetGitCred Operation = "get_git_cred"
	OpJobOpen    Operation = "job_open"
	OpStatus     Operation = "status"
	OpLock       Operation = "lock"
	OpPanic      Operation = "panic"
)

// Request is one versioned client-to-daemon message.
// The daemon must derive caller identity from the named pipe, never from Args.
type Request struct {
	Version uint16          `json:"v"`
	ID      string          `json:"id"`
	Op      Operation       `json:"op"`
	Args    json.RawMessage `json:"args,omitempty"`
}

// ProtocolError is a safe, user-facing error returned by the daemon.
// Message must never contain credential values or other secrets.
type ProtocolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Response is one versioned daemon-to-client message.
type Response struct {
	Version uint16          `json:"v"`
	ID      string          `json:"id"`
	OK      bool            `json:"ok"`
	Error   *ProtocolError  `json:"error,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Validate checks fields that are common to every request.
// Operation-specific argument validation belongs in the corresponding handler.
func (r Request) Validate() error {
	if r.Version != ProtocolVersion {
		return fmt.Errorf("unsupported IPC protocol version %d", r.Version)
	}
	if !validMessageID(r.ID) {
		return errors.New("invalid IPC request ID")
	}

	switch r.Op {
	case OpHello, OpGetCred, OpGetGitCred, OpJobOpen, OpStatus, OpLock, OpPanic:
	default:
		return fmt.Errorf("unsupported IPC operation %q", r.Op)
	}

	if len(r.Args) > 0 {
		args := bytes.TrimSpace(r.Args)
		if !json.Valid(args) || len(args) == 0 || args[0] != '{' {
			return errors.New("IPC request args must be a JSON object")
		}
	}

	return nil
}

// Validate checks the shared response envelope before a client uses its data.
func (r Response) Validate() error {
	if r.Version != ProtocolVersion {
		return fmt.Errorf("unsupported IPC protocol version %d", r.Version)
	}
	if !validMessageID(r.ID) {
		return errors.New("invalid IPC response ID")
	}
	if r.OK == (r.Error != nil) {
		return errors.New("IPC response must contain either success data or an error")
	}
	if r.Error != nil && (r.Error.Code == "" || r.Error.Message == "") {
		return errors.New("IPC error response is incomplete")
	}
	if len(r.Data) > 0 && !json.Valid(r.Data) {
		return errors.New("IPC response data is invalid JSON")
	}

	return nil
}

func validMessageID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}

	for _, char := range id {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}

	return true
}

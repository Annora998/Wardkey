package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// RoundTrip sends one request and reads its matching response.
// The caller owns the connection and is responsible for closing it.
func RoundTrip(connection io.ReadWriter, request Request, responseData any) error {
	if connection == nil {
		return errors.New("IPC connection is nil")
	}
	if err := request.Validate(); err != nil {
		return fmt.Errorf("validate IPC request: %w", err)
	}
	if err := WriteFrame(connection, request); err != nil {
		return fmt.Errorf("write IPC request: %w", err)
	}

	var response Response
	if err := ReadFrame(connection, &response); err != nil {
		return fmt.Errorf("read IPC response: %w", err)
	}
	defer clear(response.Data)

	if err := response.Validate(); err != nil {
		return fmt.Errorf("validate IPC response: %w", err)
	}
	if response.ID != request.ID {
		return errors.New("IPC response ID does not match request")
	}
	if response.Error != nil {
		return response.Error
	}
	if responseData == nil {
		return nil
	}
	if len(response.Data) == 0 {
		return errors.New("IPC response has no data")
	}
	if err := json.Unmarshal(response.Data, responseData); err != nil {
		return fmt.Errorf("decode IPC response data: %w", err)
	}
	return nil
}

// Error formats a safe daemon error for the CLI.
func (e *ProtocolError) Error() string {
	if e == nil {
		return "Wardkey IPC error"
	}
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}

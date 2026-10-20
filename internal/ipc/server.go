package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const requestTimeout = 30 * time.Second

// PeerConnection is a connected IPC stream whose peer PID comes from the OS.
type PeerConnection interface {
	io.Reader
	io.Writer
	io.Closer
	PeerPID() uint32
}

// deadlinePeerConnection allows transports to enforce the request deadline
// during blocking reads and writes.
type deadlinePeerConnection interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// RequestHandler processes a validated request.
// It must not trust identity claims inside request arguments.
type RequestHandler func(
	ctx context.Context,
	peerPID uint32,
	request Request,
) (json.RawMessage, *ProtocolError)

// ServeConnection handles one request and writes one response, then closes
// the connection.
func ServeConnection(
	ctx context.Context,
	connection PeerConnection,
	handler RequestHandler,
) error {
	if ctx == nil {
		return errors.New("IPC request context is nil")
	}
	if connection == nil {
		return errors.New("IPC connection is nil")
	}
	if handler == nil {
		return errors.New("IPC request handler is nil")
	}
	defer connection.Close()

	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	deadline, _ := requestCtx.Deadline()
	if deadlineConnection, ok := connection.(deadlinePeerConnection); ok {
		if err := deadlineConnection.SetReadDeadline(deadline); err != nil {
			return fmt.Errorf("set IPC read deadline: %w", err)
		}
	}

	var request Request
	if err := ReadFrame(connection, &request); err != nil {
		return fmt.Errorf("read IPC request: %w", err)
	}
	if err := request.Validate(); err != nil {
		return fmt.Errorf("validate IPC request: %w", err)
	}
	if err := requestCtx.Err(); err != nil {
		return err
	}

	data, protocolErr := handler(requestCtx, connection.PeerPID(), request)
	defer clear(data)

	response := Response{
		Version: ProtocolVersion,
		ID:      request.ID,
		OK:      protocolErr == nil,
		Error:   protocolErr,
		Data:    data,
	}
	if err := response.Validate(); err != nil {
		return fmt.Errorf("validate IPC response: %w", err)
	}

	if deadlineConnection, ok := connection.(deadlinePeerConnection); ok {
		if err := deadlineConnection.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("set IPC write deadline: %w", err)
		}
	}
	if err := WriteFrame(connection, response); err != nil {
		return fmt.Errorf("write IPC response: %w", err)
	}
	return nil
}

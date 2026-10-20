//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"wardkey/internal/identity"
)

// PipeClient is a bounded-I/O client connection to Wardkey's current-user pipe.
type PipeClient struct {
	handle        windows.Handle
	closeOnce     sync.Once
	closeErr      error
	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
}

// DialCurrentUserPipe connects to the named pipe for the current Windows user
// and verifies the server process before returning the connection.
func DialCurrentUserPipe() (*PipeClient, error) {
	name, err := currentUserPipeName()
	if err != nil {
		return nil, err
	}

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("encode named-pipe name: %w", err)
	}

	handle, err := windows.CreateFile(
		namePtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("connect to Wardkey named pipe: %w", err)
	}

	if err := verifyPipeServerIdentity(handle); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("verify Wardkey pipe server: %w", err)
	}

	return &PipeClient{handle: handle}, nil
}

func verifyPipeServerIdentity(pipe windows.Handle) error {
	var serverPID uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &serverPID); err != nil {
		return fmt.Errorf("read named-pipe server process ID: %w", err)
	}
	if serverPID == 0 {
		return errors.New("named-pipe server process ID is zero")
	}

	server, err := identity.InspectProcess(serverPID)
	if err != nil {
		return fmt.Errorf("inspect named-pipe server process: %w", err)
	}
	if err := server.Validate(); err != nil {
		return errors.New("named-pipe server identity is invalid")
	}
	if !strings.EqualFold(filepath.Base(server.ImagePath), "wardkey.exe") {
		return errors.New("named-pipe server is not wardkey.exe")
	}

	client, err := identity.InspectProcess(uint32(os.Getpid()))
	if err != nil {
		return fmt.Errorf("inspect Wardkey client process: %w", err)
	}
	if err := client.Validate(); err != nil {
		return errors.New("Wardkey client identity is invalid")
	}
	if server.ImageFileSHA256 != client.ImageFileSHA256 {
		return errors.New("named-pipe server executable does not match the Wardkey client")
	}

	return nil
}

// SetReadDeadline sets the deadline for future reads. A zero time clears it.
func (c *PipeClient) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

// SetWriteDeadline sets the deadline for future writes. A zero time clears it.
func (c *PipeClient) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

// Read reads bytes from the Wardkey pipe.
func (c *PipeClient) Read(buffer []byte) (int, error) {
	timeout, err := c.operationTimeout(true)
	if err != nil {
		return 0, err
	}

	n, err := readPipeOverlappedTimeout(c.handle, buffer, timeout)
	if err != nil {
		if errors.Is(err, windows.ERROR_BROKEN_PIPE) ||
			errors.Is(err, windows.ERROR_NO_DATA) ||
			errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
			return n, io.EOF
		}
		return n, err
	}
	return n, nil
}

// Write writes bytes to the Wardkey pipe.
func (c *PipeClient) Write(buffer []byte) (int, error) {
	timeout, err := c.operationTimeout(false)
	if err != nil {
		return 0, err
	}
	return writePipeOverlappedTimeout(c.handle, buffer, timeout)
}

// Close closes the pipe connection.
func (c *PipeClient) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = windows.CloseHandle(c.handle)
	})
	return c.closeErr
}

func (c *PipeClient) operationTimeout(read bool) (time.Duration, error) {
	c.deadlineMu.RLock()
	deadline := c.writeDeadline
	if read {
		deadline = c.readDeadline
	}
	c.deadlineMu.RUnlock()

	timeout := pipeOperationTimeout
	if deadline.IsZero() {
		return timeout, nil
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, os.ErrDeadlineExceeded
	}
	if remaining < timeout {
		timeout = remaining
	}
	return timeout, nil
}

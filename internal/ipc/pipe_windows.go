//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pipeNamePrefix   = `\\.\pipe\wardkey-`
	pipeBufferSize   = 4096
	pipeMaxInstances = 255
)

var (
	ErrPipeClosed = errors.New("Wardkey named pipe is closed")
	ErrPipeBusy   = errors.New("Wardkey named pipe already has an active accept")
)

// PipeListener accepts connections on a named pipe restricted to the current
// Windows user. Call Accept from one goroutine at a time.
type PipeListener struct {
	mu        sync.Mutex
	name      string
	pending   windows.Handle
	accepting windows.Handle
	closed    bool
	busy      bool
}

// PipeConn is one connected named-pipe stream.
// PeerPID is obtained from Windows, not from the request message.
type PipeConn struct {
	handle        windows.Handle
	peerPID       uint32
	closeOnce     sync.Once
	closeErr      error
	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
}

// ListenCurrentUserPipe creates the first pipe instance for the current user.
// The first-instance flag makes startup fail if another process already owns
// this pipe name.
func ListenCurrentUserPipe() (*PipeListener, error) {
	name, err := currentUserPipeName()
	if err != nil {
		return nil, err
	}

	handle, err := createPipeInstance(name, true)
	if err != nil {
		return nil, err
	}

	return &PipeListener{
		name:    name,
		pending: handle,
	}, nil
}

// Accept waits for one client, obtains its PID from Windows, and prepares the
// next pipe instance before returning the connected stream.
func (l *PipeListener) Accept() (*PipeConn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrPipeClosed
	}
	if l.busy {
		l.mu.Unlock()
		return nil, ErrPipeBusy
	}
	if l.pending == 0 {
		l.mu.Unlock()
		return nil, errors.New("Wardkey named pipe has no pending instance")
	}

	handle := l.pending
	l.pending = 0
	l.accepting = handle
	l.busy = true
	l.mu.Unlock()

	err := connectPipeOverlapped(handle)
	if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		l.finishAccept(handle)
		return nil, fmt.Errorf("connect named-pipe client: %w", err)
	}

	var peerPID uint32
	if err := windows.GetNamedPipeClientProcessId(handle, &peerPID); err != nil {
		l.finishAccept(handle)
		return nil, fmt.Errorf("get named-pipe client PID: %w", err)
	}

	nextHandle, err := createPipeInstance(l.name, false)
	if err != nil {
		l.finishAccept(handle)
		return nil, fmt.Errorf("create next named-pipe instance: %w", err)
	}

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = windows.CloseHandle(nextHandle)
		// Close owns and closes the handle while Accept is active.
		return nil, ErrPipeClosed
	}
	l.accepting = 0
	l.pending = nextHandle
	l.busy = false
	l.mu.Unlock()

	return &PipeConn{
		handle:  handle,
		peerPID: peerPID,
	}, nil
}

// Close stops future accepts and closes the pending or currently accepting
// pipe instance.
func (l *PipeListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true

	pending := l.pending
	accepting := l.accepting
	l.pending = 0
	l.accepting = 0
	l.mu.Unlock()

	var firstErr error
	if pending != 0 {
		if err := windows.CloseHandle(pending); err != nil {
			firstErr = err
		}
	}
	if accepting != 0 {
		if err := windows.CloseHandle(accepting); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// PeerPID returns the client process ID reported by Windows for this pipe.
func (c *PipeConn) PeerPID() uint32 {
	return c.peerPID
}

// SetReadDeadline sets the deadline for future reads. A zero time clears it.
func (c *PipeConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

// SetWriteDeadline sets the deadline for future writes. A zero time clears it.
func (c *PipeConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

// Read reads bytes from the connected pipe.
func (c *PipeConn) Read(buffer []byte) (int, error) {
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

// Write writes bytes to the connected pipe.
func (c *PipeConn) Write(buffer []byte) (int, error) {
	timeout, err := c.operationTimeout(false)
	if err != nil {
		return 0, err
	}
	return writePipeOverlappedTimeout(c.handle, buffer, timeout)
}

// Close closes the connected pipe.
func (c *PipeConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = windows.CloseHandle(c.handle)
	})
	return c.closeErr
}

func (c *PipeConn) operationTimeout(read bool) (time.Duration, error) {
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

func currentUserPipeName() (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY,
		&token,
	); err != nil {
		return "", fmt.Errorf("open current process token: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read current user SID: %w", err)
	}

	return pipeNamePrefix + user.User.Sid.String(), nil
}

func createPipeInstance(name string, first bool) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, fmt.Errorf("encode named-pipe name: %w", err)
	}

	sid, err := currentUserSID()
	if err != nil {
		return 0, err
	}

	securityDescriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;;GA;;;" + sid + ")",
	)
	if err != nil {
		return 0, fmt.Errorf("create named-pipe security descriptor: %w", err)
	}

	securityAttributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: securityDescriptor,
	}

	const pipeMode = windows.PIPE_TYPE_BYTE |
		windows.PIPE_READMODE_BYTE |
		windows.PIPE_WAIT |
		windows.PIPE_REJECT_REMOTE_CLIENTS

	openMode := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		openMode |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}

	handle, err := windows.CreateNamedPipe(
		namePtr,
		openMode,
		pipeMode,
		pipeMaxInstances,
		pipeBufferSize,
		pipeBufferSize,
		0,
		&securityAttributes,
	)
	if err != nil {
		return 0, fmt.Errorf("create named-pipe instance: %w", err)
	}
	return handle, nil
}

func currentUserSID() (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY,
		&token,
	); err != nil {
		return "", fmt.Errorf("open current process token: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read current user SID: %w", err)
	}

	return user.User.Sid.String(), nil
}

func (l *PipeListener) finishAccept(handle windows.Handle) {
	l.mu.Lock()
	closed := l.closed
	if l.accepting == handle {
		l.accepting = 0
	}
	l.busy = false
	l.mu.Unlock()

	// If Close already ran, it owns this handle.
	if !closed {
		_ = windows.CloseHandle(handle)
	}
}

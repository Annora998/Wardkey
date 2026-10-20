//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

const pipeOperationTimeout = 30 * time.Second

// overlappedPipeIO runs one pipe operation with a Windows OVERLAPPED event.
// A zero timeout means the operation may wait indefinitely.
func overlappedPipeIO(
	handle windows.Handle,
	timeout time.Duration,
	start func(*windows.Overlapped, *uint32) error,
) (uint32, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, fmt.Errorf("create pipe I/O event: %w", err)
	}
	defer windows.CloseHandle(event)

	overlapped := windows.Overlapped{HEvent: event}
	var transferred uint32

	err = start(&overlapped, &transferred)
	if err == nil {
		return transferred, nil
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return transferred, err
	}

	waitMilliseconds := uint32(windows.INFINITE)
	if timeout > 0 {
		milliseconds := (timeout + time.Millisecond - 1) / time.Millisecond
		if milliseconds >= time.Duration(windows.INFINITE) {
			milliseconds = time.Duration(windows.INFINITE - 1)
		}
		waitMilliseconds = uint32(milliseconds)
	}

	waitResult, waitErr := windows.WaitForSingleObject(event, waitMilliseconds)
	if waitErr != nil {
		cancelOverlappedPipeIO(handle, event, &overlapped)
		return 0, fmt.Errorf("wait for pipe I/O: %w", waitErr)
	}

	if waitResult == uint32(windows.WAIT_TIMEOUT) {
		cancelOverlappedPipeIO(handle, event, &overlapped)
		return 0, os.ErrDeadlineExceeded
	}
	if waitResult != uint32(windows.WAIT_OBJECT_0) {
		cancelOverlappedPipeIO(handle, event, &overlapped)
		return 0, fmt.Errorf("unexpected pipe I/O wait result 0x%X", waitResult)
	}

	if err := windows.GetOverlappedResult(handle, &overlapped, &transferred, false); err != nil {
		return transferred, err
	}

	runtime.KeepAlive(&overlapped)
	return transferred, nil
}

func cancelOverlappedPipeIO(
	handle windows.Handle,
	event windows.Handle,
	overlapped *windows.Overlapped,
) {
	_ = windows.CancelIoEx(handle, overlapped)
	// Wait for completion before the OVERLAPPED structure is reused or its
	// event is closed.
	_, _ = windows.WaitForSingleObject(event, windows.INFINITE)
}

func connectPipeOverlapped(handle windows.Handle) error {
	_, err := overlappedPipeIO(handle, 0, func(
		overlapped *windows.Overlapped,
		_ *uint32,
	) error {
		return windows.ConnectNamedPipe(handle, overlapped)
	})
	return err
}

func readPipeOverlapped(handle windows.Handle, buffer []byte) (int, error) {
	return readPipeOverlappedTimeout(handle, buffer, pipeOperationTimeout)
}

func readPipeOverlappedTimeout(
	handle windows.Handle,
	buffer []byte,
	timeout time.Duration,
) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}

	transferred, err := overlappedPipeIO(handle, timeout, func(
		overlapped *windows.Overlapped,
		bytesRead *uint32,
	) error {
		return windows.ReadFile(handle, buffer, bytesRead, overlapped)
	})
	runtime.KeepAlive(buffer)
	return int(transferred), err
}

func writePipeOverlapped(handle windows.Handle, buffer []byte) (int, error) {
	return writePipeOverlappedTimeout(handle, buffer, pipeOperationTimeout)
}

func writePipeOverlappedTimeout(
	handle windows.Handle,
	buffer []byte,
	timeout time.Duration,
) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}

	transferred, err := overlappedPipeIO(handle, timeout, func(
		overlapped *windows.Overlapped,
		bytesWritten *uint32,
	) error {
		return windows.WriteFile(handle, buffer, bytesWritten, overlapped)
	})
	runtime.KeepAlive(buffer)
	return int(transferred), err
}

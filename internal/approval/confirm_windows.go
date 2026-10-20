//go:build windows

package approval

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unicode"
	"unsafe"

	"wardkey/internal/ipc"
)

const (
	messageBoxYesNo          = 0x00000004
	messageBoxIconWarning    = 0x00000030
	messageBoxDefaultButton2 = 0x00000100
	messageBoxSetForeground  = 0x00010000
	messageBoxTopmost        = 0x00040000
	messageBoxResultYes      = 6
	messageBoxResultNo       = 7
)

// ConfirmRequest displays the exact credential request and asks for explicit
// consent. The caller must still verify a Windows Hello assertion afterward.
func ConfirmRequest(ctx context.Context, request Request) (bool, error) {
	if ctx == nil {
		return false, errors.New("approval context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := validateConfirmationRequest(request); err != nil {
		return false, err
	}

	user32 := syscall.NewLazyDLL("user32.dll")
	messageBox := user32.NewProc("MessageBoxW")
	if err := messageBox.Find(); err != nil {
		return false, fmt.Errorf("find Windows confirmation dialog API: %w", err)
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	if err := getConsoleWindow.Find(); err != nil {
		return false, fmt.Errorf("find console window API: %w", err)
	}
	window, _, _ := getConsoleWindow.Call()

	message := fmt.Sprintf(
		"Wardkey is requesting approval to release a credential.\n\n"+
			"Operation: %s\nProvider: %s\nProfile: %s\n"+
			"Caller: %s\nCaller file SHA-256: %x\nRequest ID: %s\n\n"+
			"Approve this exact request?",
		safeApprovalDisplay(string(request.Operation)),
		safeApprovalDisplay(request.Provider),
		safeApprovalDisplay(request.Profile),
		safeApprovalDisplay(request.Caller.ImagePath),
		request.Caller.ImageFileSHA256,
		safeApprovalDisplay(request.RequestID),
	)

	messagePtr, err := syscall.UTF16PtrFromString(message)
	if err != nil {
		return false, errors.New("encode approval confirmation message")
	}
	titlePtr, err := syscall.UTF16PtrFromString("Wardkey credential approval")
	if err != nil {
		return false, errors.New("encode approval confirmation title")
	}

	flags := uintptr(
		messageBoxYesNo |
			messageBoxIconWarning |
			messageBoxDefaultButton2 |
			messageBoxSetForeground |
			messageBoxTopmost,
	)
	result, _, callErr := messageBox.Call(
		window,
		uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		flags,
	)
	runtime.KeepAlive(messagePtr)
	runtime.KeepAlive(titlePtr)

	if result == 0 {
		if callErr != syscall.Errno(0) {
			return false, fmt.Errorf("show approval confirmation dialog: %w", callErr)
		}
		return false, errors.New("show approval confirmation dialog failed")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	switch result {
	case messageBoxResultYes:
		return true, nil
	case messageBoxResultNo:
		return false, nil
	default:
		return false, errors.New("approval confirmation dialog returned an unexpected result")
	}
}

func validateConfirmationRequest(request Request) error {
	envelope := ipc.Request{
		Version: ipc.ProtocolVersion,
		ID:      request.RequestID,
		Op:      request.Operation,
	}
	if err := envelope.Validate(); err != nil {
		return fmt.Errorf("invalid approval request: %w", err)
	}
	if request.Operation != ipc.OpGetCred && request.Operation != ipc.OpGetGitCred {
		return errors.New("operation cannot be approved for credential release")
	}
	if strings.TrimSpace(request.Provider) == "" ||
		len(request.Provider) > 128 ||
		strings.TrimSpace(request.Profile) == "" ||
		len(request.Profile) > 128 {
		return errors.New("approval request provider or profile is invalid")
	}
	if err := request.Caller.Validate(); err != nil {
		return fmt.Errorf("approval caller identity is invalid: %w", err)
	}
	return nil
}

func safeApprovalDisplay(value string) string {
	var result strings.Builder
	result.Grow(len(value))

	for _, char := range value {
		if unicode.IsControl(char) {
			result.WriteByte(' ')
		} else {
			result.WriteRune(char)
		}
	}

	cleaned := strings.TrimSpace(result.String())
	runes := []rune(cleaned)
	if len(runes) > 512 {
		cleaned = string(runes[:512]) + "…"
	}
	return cleaned
}

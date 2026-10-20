//go:build !windows

package approval

import (
	"context"
	"errors"
)

// ConfirmRequest is available only in the Windows build.
func ConfirmRequest(context.Context, Request) (bool, error) {
	return false, errors.New("interactive approval is supported only on Windows")
}

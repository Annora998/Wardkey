//go:build !windows

package approval

import (
	"context"
	"errors"
)

func Enroll(*Store, []byte) error {
	return errors.New("Windows Hello enrollment is supported only on Windows")
}

func Approve(context.Context, *Store, []byte, Request) (bool, error) {
	return false, errors.New("Windows Hello approval is supported only on Windows")
}

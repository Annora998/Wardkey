//go:build windows

package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"wardkey/internal/identity"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "get" {
		fmt.Fprintln(os.Stderr, "expected Git credential helper action 'get'")
		os.Exit(2)
	}

	if _, err := io.Copy(io.Discard, io.LimitReader(os.Stdin, 64<<10)); err != nil {
		fmt.Fprintln(os.Stderr, "could not read Git credential request")
		os.Exit(1)
	}

	parentPID, err := identity.ParentProcessID(uint32(os.Getpid()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not inspect helper parent process")
		os.Exit(1)
	}

	parent, err := identity.InspectProcess(parentPID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not inspect helper parent executable")
		os.Exit(1)
	}

	fmt.Fprintf(
		os.Stderr,
		"Git helper parent: %s (PID %d, file-sha256:%s)\n",
		parent.ImagePath,
		parent.PID,
		hex.EncodeToString(parent.ImageFileSHA256[:]),
	)
}

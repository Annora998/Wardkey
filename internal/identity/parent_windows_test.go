//go:build windows

package identity

import (
	"os"
	"testing"
)

func TestParentProcessIDMatchesOperatingSystem(t *testing.T) {
	processID := uint32(os.Getpid())
	wantParentID := uint32(os.Getppid())

	gotParentID, err := ParentProcessID(processID)
	if err != nil {
		t.Fatalf("ParentProcessID(%d): %v", processID, err)
	}
	if gotParentID != wantParentID {
		t.Fatalf("ParentProcessID(%d) = %d, want %d", processID, gotParentID, wantParentID)
	}
}

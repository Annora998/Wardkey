package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"wardkey/internal/ipc"
)

type brokerStatus struct {
	Protocol uint16 `json:"protocol"`
	Locked   bool   `json:"locked"`
}

func showStatus(out io.Writer) error {
	connection, err := ipc.DialCurrentUserPipe()
	if err != nil {
		return fmt.Errorf("connect to Wardkey broker: %w", err)
	}
	defer connection.Close()

	var requestID [16]byte
	if _, err := rand.Read(requestID[:]); err != nil {
		return fmt.Errorf("create IPC request ID: %w", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	if err := connection.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("set IPC read deadline: %w", err)
	}
	if err := connection.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set IPC write deadline: %w", err)
	}

	request := ipc.Request{
		Version: ipc.ProtocolVersion,
		ID:      hex.EncodeToString(requestID[:]),
		Op:      ipc.OpStatus,
	}

	var status brokerStatus
	if err := ipc.RoundTrip(connection, request, &status); err != nil {
		return fmt.Errorf("request broker status: %w", err)
	}
	if status.Protocol != ipc.ProtocolVersion {
		return fmt.Errorf("broker returned unexpected protocol version %d", status.Protocol)
	}

	_, err = fmt.Fprintf(out, "Broker status: locked=%t (protocol v%d)\n", status.Locked, status.Protocol)
	return err
}

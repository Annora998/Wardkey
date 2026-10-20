package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"wardkey/internal/ipc"
)

type brokerLockStatus struct {
	Locked bool `json:"locked"`
}

func lockBroker(out io.Writer) error {
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
		Op:      ipc.OpLock,
	}

	var result brokerLockStatus
	if err := ipc.RoundTrip(connection, request, &result); err != nil {
		return fmt.Errorf("lock broker: %w", err)
	}
	if !result.Locked {
		return fmt.Errorf("broker did not confirm that it locked the vault")
	}

	_, err = fmt.Fprintln(out, "Broker locked.")
	return err
}

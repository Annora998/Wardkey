//go:build windows

package broker

import (
	"context"
	"fmt"
	"log"
	"sync"

	"wardkey/internal/ipc"
)

const maxConcurrentClients = 32

// Serve accepts local named-pipe clients and dispatches each connection to the
// IPC server. It returns when the context is cancelled or the listener fails.
func Serve(ctx context.Context, handler *Handler) error {
	if ctx == nil {
		return fmt.Errorf("broker context is nil")
	}
	if handler == nil {
		return fmt.Errorf("broker handler is nil")
	}

	// Registered before listener cleanup so it runs only after active workers
	// have stopped.
	defer handler.Close()

	listener, err := ipc.ListenCurrentUserPipe()
	if err != nil {
		return fmt.Errorf("start Wardkey named-pipe listener: %w", err)
	}

	stopWatcher := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stopWatcher:
		}
	}()

	var workers sync.WaitGroup
	slots := make(chan struct{}, maxConcurrentClients)

	defer func() {
		close(stopWatcher)
		_ = listener.Close()
		workers.Wait()
	}()

	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept Wardkey named-pipe client: %w", err)
		}

		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func(connection *ipc.PipeConn) {
				defer workers.Done()
				defer func() { <-slots }()

				connectionFinished := make(chan struct{})
				go func() {
					select {
					case <-ctx.Done():
						_ = connection.Close()
					case <-connectionFinished:
					}
				}()

				if err := ipc.ServeConnection(ctx, connection, handler.Handle); err != nil {
					log.Printf("Wardkey IPC request failed: %v", err)
				}
				close(connectionFinished)
			}(connection)

		default:
			// Keep the server bounded under a burst of local connections.
			_ = connection.Close()
		}
	}
}

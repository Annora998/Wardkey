package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaxFrameSize = 1 << 20 // 1 MiB

var (
	ErrFrameTooLarge = errors.New("IPC frame exceeds maximum size")
	ErrEmptyFrame    = errors.New("IPC frame is empty")
)

// WriteFrame writes a little-endian uint32 length followed by one JSON value.
func WriteFrame(w io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode IPC frame: %w", err)
	}
	defer clear(payload)

	if len(payload) == 0 {
		return ErrEmptyFrame
	}
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}

	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(payload)))

	if err := writeAll(w, header[:]); err != nil {
		return fmt.Errorf("write IPC header: %w", err)
	}
	if err := writeAll(w, payload); err != nil {
		return fmt.Errorf("write IPC payload: %w", err)
	}
	return nil
}

// ReadFrame checks the announced size before allocating the payload buffer.
func ReadFrame(r io.Reader, destination any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fmt.Errorf("read IPC header: %w", err)
	}

	size := binary.LittleEndian.Uint32(header[:])
	if size == 0 {
		return ErrEmptyFrame
	}
	if size > MaxFrameSize {
		return ErrFrameTooLarge
	}

	payload := make([]byte, int(size))
	defer clear(payload)

	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("read IPC payload: %w", err)
	}
	if err := json.Unmarshal(payload, destination); err != nil {
		return fmt.Errorf("decode IPC payload: %w", err)
	}
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return errors.New("invalid write count")
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

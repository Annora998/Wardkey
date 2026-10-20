package ipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestWriteFrameAndReadFrame(t *testing.T) {
	type message struct {
		Version int    `json:"version"`
		Command string `json:"command"`
	}

	want := message{Version: 1, Command: "status"}

	var wire bytes.Buffer
	if err := WriteFrame(&wire, want); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}

	var got message
	if err := ReadFrame(&wire, &got); err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if got != want {
		t.Fatalf("ReadFrame() = %#v, want %#v", got, want)
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	var wire bytes.Buffer
	value := struct {
		Data string `json:"data"`
	}{Data: strings.Repeat("x", MaxFrameSize)}

	err := WriteFrame(&wire, value)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFrame() error = %v, want ErrFrameTooLarge", err)
	}
	if wire.Len() != 0 {
		t.Fatalf("WriteFrame() wrote %d bytes before rejecting payload", wire.Len())
	}
}

func TestReadFrameRejectsInvalidLengths(t *testing.T) {
	tests := []struct {
		name string
		size uint32
		want error
	}{
		{name: "empty", size: 0, want: ErrEmptyFrame},
		{name: "too large", size: MaxFrameSize + 1, want: ErrFrameTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wire bytes.Buffer
			var header [4]byte
			binary.LittleEndian.PutUint32(header[:], tt.size)
			wire.Write(header[:])

			var destination map[string]any
			err := ReadFrame(&wire, &destination)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ReadFrame() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestReadFrameRejectsTruncatedInput(t *testing.T) {
	t.Run("header", func(t *testing.T) {
		var destination map[string]any
		err := ReadFrame(bytes.NewReader([]byte{1, 2}), &destination)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("ReadFrame() error = %v, want io.ErrUnexpectedEOF", err)
		}
	})

	t.Run("payload", func(t *testing.T) {
		var wire bytes.Buffer
		var header [4]byte
		binary.LittleEndian.PutUint32(header[:], 5)
		wire.Write(header[:])
		wire.WriteString("{}")

		var destination map[string]any
		err := ReadFrame(&wire, &destination)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("ReadFrame() error = %v, want io.ErrUnexpectedEOF", err)
		}
	})
}

func TestReadFrameRejectsInvalidJSON(t *testing.T) {
	var wire bytes.Buffer
	var header [4]byte
	payload := []byte("{invalid")
	binary.LittleEndian.PutUint32(header[:], uint32(len(payload)))
	wire.Write(header[:])
	wire.Write(payload)

	var destination map[string]any
	if err := ReadFrame(&wire, &destination); err == nil {
		t.Fatal("ReadFrame() error = nil, want invalid JSON error")
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{2, 0, 0, 0, '{', '}'})
	f.Add([]byte{1, 0, 0, 0, 'x'})

	f.Fuzz(func(t *testing.T, data []byte) {
		var destination map[string]any
		_ = ReadFrame(bytes.NewReader(data), &destination)
	})
}

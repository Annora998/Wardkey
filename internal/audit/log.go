package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"wardkey/internal/vault"
)

const (
	MaxLogSize    = 16 << 20
	maxRecordLine = 64 << 10
)

var (
	ErrLogTooLarge  = errors.New("audit log exceeds maximum size")
	ErrLogIntegrity = errors.New("audit log integrity check failed")
)

// Logger appends and verifies a local HMAC-chained JSONL audit log.
// It does not retain the audit key.
type Logger struct {
	mu   sync.Mutex
	path string
}

// NewLogger creates or opens the log at path and ensures its directory and
// file use Wardkey's private Windows ACL protections.
func NewLogger(path string) (*Logger, error) {
	if path == "" {
		return nil, errors.New("audit log path is required")
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve audit log path: %w", err)
	}

	logger := &Logger{path: filepath.Clean(absolute)}
	if err := ensurePrivateLogFile(logger.path); err != nil {
		return nil, fmt.Errorf("prepare audit log: %w", err)
	}

	return logger, nil
}

// Verify checks the complete log chain using key. An empty log is valid.
func (l *Logger) Verify(key []byte) error {
	if l == nil {
		return errors.New("audit logger is unavailable")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	_, _, _, err := l.verifyLocked(key)
	return err
}

// Append verifies the existing chain, appends one event, and syncs it to disk.
// The caller must not modify key until this method returns.
func (l *Logger) Append(key []byte, event Event) error {
	if l == nil {
		return errors.New("audit logger is unavailable")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	sequence, previousMAC, size, err := l.verifyLocked(key)
	if err != nil {
		return err
	}
	if sequence == ^uint64(0) {
		return fmt.Errorf("%w: sequence number exhausted", ErrLogIntegrity)
	}

	entry, err := newRecord(key, sequence+1, previousMAC, event, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("create audit record: %w", err)
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode audit record: %w", err)
	}
	if len(line)+1 > maxRecordLine {
		return fmt.Errorf("%w: record is too large", ErrLogIntegrity)
	}
	if size+int64(len(line)+1) > MaxLogSize {
		return ErrLogTooLarge
	}
	line = append(line, '\n')

	if err := ensurePrivateLogFile(l.path); err != nil {
		return fmt.Errorf("secure audit log before append: %w", err)
	}

	file, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("open audit log for append: %w", err)
	}

	written, writeErr := file.Write(line)
	if writeErr == nil && written != len(line) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()

	if writeErr != nil {
		return fmt.Errorf("append audit record: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close audit log: %w", closeErr)
	}

	return nil
}

func (l *Logger) verifyLocked(key []byte) (uint64, []byte, int64, error) {
	if len(key) != 32 {
		return 0, nil, 0, errInvalidKey
	}
	if err := ensurePrivateLogFile(l.path); err != nil {
		return 0, nil, 0, fmt.Errorf("secure audit log before verification: %w", err)
	}

	file, err := os.Open(l.path)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return 0, nil, 0, fmt.Errorf("inspect audit log: %w", err)
	}
	if !info.Mode().IsRegular() {
		return 0, nil, 0, fmt.Errorf("%w: log is not a regular file", ErrLogIntegrity)
	}
	if info.Size() > MaxLogSize {
		return 0, nil, 0, ErrLogTooLarge
	}

	data, err := io.ReadAll(io.LimitReader(file, MaxLogSize+1))
	if err != nil {
		return 0, nil, 0, fmt.Errorf("read audit log: %w", err)
	}
	if len(data) > MaxLogSize {
		return 0, nil, 0, ErrLogTooLarge
	}
	if len(data) == 0 {
		return 0, nil, 0, nil
	}
	if data[len(data)-1] != '\n' {
		return 0, nil, 0, fmt.Errorf("%w: final record is incomplete", ErrLogIntegrity)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxRecordLine)

	var sequence uint64
	var previousMAC []byte

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			return 0, nil, 0, fmt.Errorf("%w: empty record", ErrLogIntegrity)
		}

		entry, err := decodeRecord(line)
		if err != nil {
			return 0, nil, 0, fmt.Errorf("%w: %v", ErrLogIntegrity, err)
		}
		if sequence == ^uint64(0) {
			return 0, nil, 0, fmt.Errorf("%w: sequence number exhausted", ErrLogIntegrity)
		}

		verifiedMAC, err := verifyRecord(key, entry, sequence+1, previousMAC)
		if err != nil {
			return 0, nil, 0, fmt.Errorf("%w: %v", ErrLogIntegrity, err)
		}

		sequence++
		previousMAC = verifiedMAC
	}
	if err := scanner.Err(); err != nil {
		return 0, nil, 0, fmt.Errorf("%w: read record: %v", ErrLogIntegrity, err)
	}

	return sequence, previousMAC, int64(len(data)), nil
}

func decodeRecord(line []byte) (record, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()

	var entry record
	if err := decoder.Decode(&entry); err != nil {
		return record{}, fmt.Errorf("decode record: %w", err)
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return record{}, errors.New("record contains trailing data")
	}

	canonical, err := json.Marshal(entry)
	if err != nil {
		return record{}, fmt.Errorf("canonicalize record: %w", err)
	}
	if !bytes.Equal(line, canonical) {
		return record{}, errors.New("record encoding is not canonical")
	}

	return entry, nil
}

func ensurePrivateLogFile(path string) error {
	directory := filepath.Dir(path)
	if err := vault.EnsurePrivateDirectory(directory); err != nil {
		return fmt.Errorf("secure audit directory: %w", err)
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if createErr != nil && !errors.Is(createErr, os.ErrExist) {
			return fmt.Errorf("create audit log: %w", createErr)
		}
		if createErr == nil {
			if closeErr := file.Close(); closeErr != nil {
				return fmt.Errorf("close new audit log: %w", closeErr)
			}
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect audit log path: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: path is not a regular file", ErrLogIntegrity)
	}

	if err := vault.RestrictExistingPrivateFile(path); err != nil {
		return fmt.Errorf("restrict audit log permissions: %w", err)
	}
	return nil
}

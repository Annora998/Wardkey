package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const recordVersion = 1

var (
	errInvalidKey    = errors.New("invalid audit key")
	errInvalidRecord = errors.New("invalid audit record")
)

type Event struct {
	Type             string `json:"type"`
	Outcome          string `json:"outcome"`
	Provider         string `json:"provider,omitempty"`
	Profile          string `json:"profile,omitempty"`
	CallerFileSHA256 string `json:"caller_file_sha256,omitempty"`
}

type recordData struct {
	Version      uint8  `json:"version"`
	Sequence     uint64 `json:"sequence"`
	TimeUnixNano int64  `json:"time_unix_nano"`
	Event        Event  `json:"event"`
	PreviousMAC  string `json:"previous_mac"`
}

type record struct {
	Version      uint8  `json:"version"`
	Sequence     uint64 `json:"sequence"`
	TimeUnixNano int64  `json:"time_unix_nano"`
	Event        Event  `json:"event"`
	PreviousMAC  string `json:"previous_mac"`
	MAC          string `json:"mac"`
}

func newRecord(
	key []byte,
	sequence uint64,
	previousMAC []byte,
	event Event,
	at time.Time,
) (record, error) {
	if len(key) != 32 {
		return record{}, errInvalidKey
	}
	if sequence == 0 {
		return record{}, fmt.Errorf("%w: sequence must be positive", errInvalidRecord)
	}
	if sequence == 1 && len(previousMAC) != 0 {
		return record{}, fmt.Errorf("%w: first record cannot have a previous MAC", errInvalidRecord)
	}
	if sequence > 1 && len(previousMAC) != sha256.Size {
		return record{}, fmt.Errorf("%w: previous MAC has the wrong length", errInvalidRecord)
	}
	if err := event.validate(); err != nil {
		return record{}, err
	}

	timestamp := at.UTC().UnixNano()
	if timestamp <= 0 {
		return record{}, fmt.Errorf("%w: timestamp is invalid", errInvalidRecord)
	}

	data := recordData{
		Version:      recordVersion,
		Sequence:     sequence,
		TimeUnixNano: timestamp,
		Event:        event,
	}
	if len(previousMAC) > 0 {
		data.PreviousMAC = hex.EncodeToString(previousMAC)
	}

	mac, err := calculateMAC(key, data)
	if err != nil {
		return record{}, err
	}

	return record{
		Version:      data.Version,
		Sequence:     data.Sequence,
		TimeUnixNano: data.TimeUnixNano,
		Event:        data.Event,
		PreviousMAC:  data.PreviousMAC,
		MAC:          hex.EncodeToString(mac),
	}, nil
}

func verifyRecord(
	key []byte,
	got record,
	expectedSequence uint64,
	expectedPreviousMAC []byte,
) ([]byte, error) {
	if len(key) != 32 {
		return nil, errInvalidKey
	}
	if got.Version != recordVersion ||
		got.Sequence != expectedSequence ||
		got.TimeUnixNano <= 0 {
		return nil, errInvalidRecord
	}
	if err := got.Event.validate(); err != nil {
		return nil, err
	}

	wantPrevious := ""
	if len(expectedPreviousMAC) > 0 {
		wantPrevious = hex.EncodeToString(expectedPreviousMAC)
	}
	if got.PreviousMAC != wantPrevious {
		return nil, fmt.Errorf("%w: previous MAC does not match", errInvalidRecord)
	}

	gotMAC, err := hex.DecodeString(got.MAC)
	if err != nil || len(gotMAC) != sha256.Size {
		return nil, fmt.Errorf("%w: MAC encoding is invalid", errInvalidRecord)
	}

	data := recordData{
		Version:      got.Version,
		Sequence:     got.Sequence,
		TimeUnixNano: got.TimeUnixNano,
		Event:        got.Event,
		PreviousMAC:  got.PreviousMAC,
	}
	wantMAC, err := calculateMAC(key, data)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(gotMAC, wantMAC) {
		return nil, fmt.Errorf("%w: MAC verification failed", errInvalidRecord)
	}

	return gotMAC, nil
}

func calculateMAC(key []byte, data recordData) ([]byte, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("encode audit record: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(encoded); err != nil {
		return nil, fmt.Errorf("calculate audit record MAC: %w", err)
	}
	return mac.Sum(nil), nil
}

func (e Event) validate() error {
	if !validLabel(e.Type, 64) || !validLabel(e.Outcome, 32) {
		return fmt.Errorf("%w: event type or outcome is invalid", errInvalidRecord)
	}
	if !validText(e.Provider, 128) ||
		!validText(e.Profile, 128) {
		return fmt.Errorf("%w: provider or profile is invalid", errInvalidRecord)
	}
	if e.CallerFileSHA256 != "" {
		decoded, err := hex.DecodeString(e.CallerFileSHA256)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("%w: caller file hash is invalid", errInvalidRecord)
		}
	}
	return nil
}

func validLabel(value string, maxLength int) bool {
	if len(value) == 0 || len(value) > maxLength {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func validText(value string, maxLength int) bool {
	if len(value) > maxLength || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

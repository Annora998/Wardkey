package audit

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRecordChainVerifiesAndDetectsTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, 32)
	firstEvent := Event{
		Type:             "credential.request",
		Outcome:          "denied",
		Provider:         "generic",
		Profile:          "demo",
		CallerFileSHA256: strings.Repeat("a", 64),
	}

	first, err := newRecord(key, 1, nil, firstEvent, time.Now())
	if err != nil {
		t.Fatalf("newRecord(first) error = %v", err)
	}

	firstMAC, err := verifyRecord(key, first, 1, nil)
	if err != nil {
		t.Fatalf("verifyRecord(first) error = %v", err)
	}

	secondEvent := Event{
		Type:    "vault.lock",
		Outcome: "success",
	}
	second, err := newRecord(key, 2, firstMAC, secondEvent, time.Now())
	if err != nil {
		t.Fatalf("newRecord(second) error = %v", err)
	}

	secondMAC, err := verifyRecord(key, second, 2, firstMAC)
	if err != nil {
		t.Fatalf("verifyRecord(second) error = %v", err)
	}
	if len(secondMAC) != 32 {
		t.Fatalf("second MAC length = %d, want 32", len(secondMAC))
	}

	tampered := second
	tampered.Event.Outcome = "allowed"
	if _, err := verifyRecord(key, tampered, 2, firstMAC); !errors.Is(err, errInvalidRecord) {
		t.Fatalf("verifyRecord(tampered) error = %v, want errInvalidRecord", err)
	}
}

func TestRecordRejectsWrongKeyAndBrokenChain(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	record, err := newRecord(
		key,
		1,
		nil,
		Event{Type: "vault.unlock", Outcome: "success"},
		time.Now(),
	)
	if err != nil {
		t.Fatalf("newRecord() error = %v", err)
	}

	wrongKey := bytes.Repeat([]byte{0x43}, 32)
	if _, err := verifyRecord(wrongKey, record, 1, nil); !errors.Is(err, errInvalidRecord) {
		t.Fatalf("verifyRecord(wrong key) error = %v, want errInvalidRecord", err)
	}

	wrongPreviousMAC := bytes.Repeat([]byte{0x44}, 32)
	if _, err := verifyRecord(key, record, 1, wrongPreviousMAC); !errors.Is(err, errInvalidRecord) {
		t.Fatalf("verifyRecord(wrong chain) error = %v, want errInvalidRecord", err)
	}
}

func TestNewRecordRejectsInvalidEvent(t *testing.T) {
	key := bytes.Repeat([]byte{0x45}, 32)

	_, err := newRecord(
		key,
		1,
		nil,
		Event{Type: "credential request", Outcome: "denied"},
		time.Now(),
	)
	if !errors.Is(err, errInvalidRecord) {
		t.Fatalf("newRecord() error = %v, want errInvalidRecord", err)
	}
}

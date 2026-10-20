package broker

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"wardkey/internal/vault"
)

func TestSessionLockRetainsAuditKeyUntilClose(t *testing.T) {
	session := NewSession()
	auditKey := bytes.Repeat([]byte{0x5A}, vault.AuditKeySize)

	if err := session.UnlockWithAuditKey([]vault.Entry{}, auditKey); err != nil {
		t.Fatalf("UnlockWithAuditKey() error = %v", err)
	}

	if session.Locked() {
		t.Fatal("session is locked after successful unlock")
	}

	session.Lock()

	if !session.Locked() {
		t.Fatal("session is unlocked after Lock()")
	}

	err := session.WithAuditKey(func(got []byte) error {
		if !bytes.Equal(got, auditKey) {
			t.Fatal("locked session returned a different audit key")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithAuditKey() while locked error = %v", err)
	}

	session.Close()

	if !session.Locked() {
		t.Fatal("session is unlocked after Close()")
	}
	if !bytes.Equal(auditKey, make([]byte, vault.AuditKeySize)) {
		t.Fatal("Close() did not clear the transferred audit key")
	}

	err = session.WithAuditKey(func([]byte) error { return nil })
	if !errors.Is(err, ErrSessionAuditKeyUnavailable) {
		t.Fatalf("WithAuditKey() after Close() error = %v, want ErrSessionAuditKeyUnavailable", err)
	}
}

func TestSessionUnlockWithAuditKeyRejectsInvalidKeyLength(t *testing.T) {
	session := NewSession()
	err := session.UnlockWithAuditKey([]vault.Entry{}, make([]byte, vault.AuditKeySize-1))
	if err == nil {
		t.Fatal("UnlockWithAuditKey() accepted an invalid key")
	}
	if !session.Locked() {
		t.Fatal("session unlocked after rejecting an invalid key")
	}
}

func TestSessionLockWaitsForActiveCredentialUseAndClearsValue(t *testing.T) {
	session := NewSession()
	secret := []byte("dummy-session-secret")
	auditKey := bytes.Repeat([]byte{0x3C}, vault.AuditKeySize)

	entries := []vault.Entry{
		{
			Provider: "generic",
			Name:     "session-lock-test",
			Value:    secret,
		},
	}
	if err := session.UnlockWithAuditKey(entries, auditKey); err != nil {
		t.Fatalf("UnlockWithAuditKey() error = %v", err)
	}
	defer session.Close()

	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	callbackResult := make(chan error, 1)

	go func() {
		callbackResult <- session.WithCredential(
			"generic",
			"session-lock-test",
			func(value []byte) error {
				close(callbackEntered)
				<-releaseCallback

				if !bytes.Equal(value, []byte("dummy-session-secret")) {
					return errors.New("credential value changed while callback was active")
				}
				return nil
			},
		)
	}()

	select {
	case <-callbackEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("credential callback did not start")
	}

	lockStarted := make(chan struct{})
	lockDone := make(chan struct{})
	go func() {
		close(lockStarted)
		session.Lock()
		close(lockDone)
	}()

	<-lockStarted

	select {
	case <-lockDone:
		t.Fatal("Lock() returned while a credential callback was active")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseCallback)

	select {
	case err := <-callbackResult:
		if err != nil {
			t.Fatalf("WithCredential() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("credential callback did not finish")
	}

	select {
	case <-lockDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Lock() did not finish after the credential callback returned")
	}

	if !session.Locked() {
		t.Fatal("session is unlocked after Lock()")
	}
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("Lock() did not clear the credential value")
	}
}

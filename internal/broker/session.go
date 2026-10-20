package broker

import (
	"errors"
	"sync"

	"wardkey/internal/vault"
)

var (
	ErrSessionLocked                 = errors.New("broker session is locked")
	ErrCredentialNotFound            = errors.New("credential was not found")
	ErrSessionAuditKeyUnavailable    = errors.New("broker session audit key is unavailable")
	ErrSessionApprovalKeyUnavailable = errors.New("broker session approval key is unavailable")
)

// Session holds decrypted vault entries and derived keys in memory.
// Lock clears credentials and the approval key but retains the audit key until
// Close so the broker can record requests rejected while locked.
type Session struct {
	mu          sync.RWMutex
	entries     []vault.Entry
	auditKey    []byte
	approvalKey []byte
	locked      bool
}

// NewSession creates a session that starts locked.
func NewSession() *Session {
	return &Session{locked: true}
}

// Unlock replaces the session entries. Ownership of entries transfers to the
// session.
func (s *Session) Unlock(entries []vault.Entry) error {
	if s == nil {
		return errors.New("broker session is unavailable")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.clearLocked()
	s.entries = entries
	s.locked = false
	return nil
}

// UnlockWithAuditKey replaces the session contents and takes ownership of
// entries and auditKey if it succeeds. It leaves approval unavailable.
// The caller must not use either slice after success.
func (s *Session) UnlockWithAuditKey(entries []vault.Entry, auditKey []byte) error {
	if s == nil {
		return errors.New("broker session is unavailable")
	}
	if len(auditKey) != vault.AuditKeySize {
		return errors.New("invalid broker session audit key")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.clearLocked()
	s.entries = entries
	s.auditKey = auditKey
	s.locked = false
	return nil
}

// UnlockWithKeys replaces the session contents and takes ownership of entries
// and both keys if it succeeds. The caller must not use these slices afterward.
func (s *Session) UnlockWithKeys(
	entries []vault.Entry,
	auditKey []byte,
	approvalKey []byte,
) error {
	if s == nil {
		return errors.New("broker session is unavailable")
	}
	if len(auditKey) != vault.AuditKeySize {
		return errors.New("invalid broker session audit key")
	}
	if len(approvalKey) != vault.ApprovalKeySize {
		return errors.New("invalid broker session approval key")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.clearLocked()
	s.entries = entries
	s.auditKey = auditKey
	s.approvalKey = approvalKey
	s.locked = false
	return nil
}

// Lock clears decrypted credentials and the approval key. It retains the
// audit key until Close. It waits for active callbacks to finish.
func (s *Session) Lock() {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	clearSessionEntries(s.entries)
	s.entries = nil
	clear(s.approvalKey)
	s.approvalKey = nil
	s.locked = true
}

// Close clears decrypted credentials and all retained keys, then locks the
// session. Call it when the broker is shutting down.
func (s *Session) Close() {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.clearLocked()
	s.locked = true
}

func (s *Session) clearLocked() {
	clearSessionEntries(s.entries)
	clear(s.auditKey)
	clear(s.approvalKey)
	s.entries = nil
	s.auditKey = nil
	s.approvalKey = nil
}

// Locked reports whether the session is locked.
func (s *Session) Locked() bool {
	if s == nil {
		return true
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.locked
}

// WithCredential calls use with the exact matching provider and name while
// holding a read lock. The callback must use the value synchronously and must
// not retain or modify it. Lock waits until the callback returns.
func (s *Session) WithCredential(
	provider string,
	name string,
	use func(value []byte) error,
) error {
	if s == nil {
		return ErrSessionLocked
	}
	if provider == "" || name == "" {
		return errors.New("credential provider and name are required")
	}
	if use == nil {
		return errors.New("credential callback is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.locked {
		return ErrSessionLocked
	}

	for i := range s.entries {
		entry := &s.entries[i]
		if entry.Provider == provider && entry.Name == name {
			return use(entry.Value)
		}
	}

	return ErrCredentialNotFound
}

// WithAuditKey calls use with the session audit key while holding a read lock.
// The key remains available while locked, but not after Close. The callback
// must use it synchronously and must not retain or modify it.
func (s *Session) WithAuditKey(use func(auditKey []byte) error) error {
	if s == nil {
		return ErrSessionAuditKeyUnavailable
	}
	if use == nil {
		return errors.New("audit key callback is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.auditKey) != vault.AuditKeySize {
		return ErrSessionAuditKeyUnavailable
	}

	return use(s.auditKey)
}

// WithApprovalKey calls use with the session approval key while holding a read
// lock. The callback must use it synchronously and must not retain or modify it.
func (s *Session) WithApprovalKey(use func(approvalKey []byte) error) error {
	if s == nil {
		return ErrSessionApprovalKeyUnavailable
	}
	if use == nil {
		return errors.New("approval key callback is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.locked {
		return ErrSessionLocked
	}
	if len(s.approvalKey) != vault.ApprovalKeySize {
		return ErrSessionApprovalKeyUnavailable
	}

	return use(s.approvalKey)
}

func clearSessionEntries(entries []vault.Entry) {
	for i := range entries {
		clear(entries[i].Value)
		entries[i] = vault.Entry{}
	}
}

package broker

import (
	"errors"

	"wardkey/internal/vault"
)

// IsDecoy reports whether the exact provider and name match a decoy entry.
// It never exposes the entry's value.
func (s *Session) IsDecoy(provider, name string) (bool, error) {
	if s == nil {
		return false, ErrSessionLocked
	}
	if provider == "" || name == "" {
		return false, errors.New("credential provider and name are required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.locked {
		return false, ErrSessionLocked
	}

	for i := range s.entries {
		entry := &s.entries[i]
		if entry.Provider == provider && entry.Name == name {
			return entry.Decoy, nil
		}
	}

	return false, nil
}

// Keep the vault reference explicit here so this file's API remains tied to
// the entry type used by Session.
var _ = vault.Entry{}

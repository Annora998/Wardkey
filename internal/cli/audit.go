package cli

import (
	"fmt"

	"wardkey/internal/audit"
)

func recordVaultUnlock(path string, auditKey []byte) error {
	logger, err := audit.NewLogger(path)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}

	if err := logger.Verify(auditKey); err != nil {
		return fmt.Errorf("verify audit log: %w", err)
	}

	if err := logger.Append(auditKey, audit.Event{
		Type:    "vault.unlock",
		Outcome: "success",
	}); err != nil {
		return fmt.Errorf("record vault unlock: %w", err)
	}

	return nil
}

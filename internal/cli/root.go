package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"wardkey/internal/approval"
	"wardkey/internal/audit"
	"wardkey/internal/broker"
	"wardkey/internal/config"
	"wardkey/internal/vault"
)

const version = "0.1.0-dev"

// Execute handles the command and writes user-facing output to out.
func Execute(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("no command specified; run 'wardkey help'")
	}

	switch args[0] {
	case "help", "--help", "-h":
		_, err := fmt.Fprintln(out, `Wardkey - local credential broker

Usage:
  wardkey <command>

Commands:
  help       Show this help
  version    Show the version
  doctor     Check whether the configured vault volume supports Windows ACLs
  init       Create a new encrypted vault
  add [--decoy] <provider> <name>  Add a credential or decoy (value hidden)
  list       List credential metadata (values hidden)
  remove     Remove a credential
  migrate    Re-encrypt an existing vault with the current format
  audit verify  Verify the local audit log
  approval enroll  Enroll Windows Hello for approval-required requests
  aws-credential-process <profile>  Supply AWS credentials to AWS CLI
  serve      Start the local broker
  status     Show the running broker status
  lock       Lock the running broker vault
  fingerprint <path>  Print an executable's policy identity`)
		return err

	case "version":
		_, err := fmt.Fprintln(out, "wardkey", version)
		return err

	case "aws-credential-process":
		return ExecuteAWSCredentialProcess(args[1:], out)

	case "doctor":
		home, err := config.DefaultHome()
		if err != nil {
			return fmt.Errorf("resolve Wardkey home: %w", err)
		}

		vaultPath := filepath.Join(home.Path, "vault.wkv")
		if err := vault.CheckStorageFilesystem(vaultPath); err != nil {
			return fmt.Errorf("vault storage filesystem check failed: %w", err)
		}

		if home.Development {
			if _, err := fmt.Fprintln(out, home.Warning); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out, "Storage volume supports persistent Windows ACLs."); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, "No vault was created or opened.")
		return err

	case "init":
		return initializeVault(out)

	case "add":
		return addCredential(args, out)

	case "list":
		return listCredentials(args, out)

	case "remove":
		return removeCredential(args, out)

	case "migrate":
		if len(args) != 1 {
			return errors.New("'migrate' does not accept additional arguments")
		}
		return migrateVault(out)

	case "audit":
		if len(args) != 2 || args[1] != "verify" {
			return errors.New("usage: wardkey audit verify")
		}
		return verifyAuditLog(out)

	case "approval":
		if len(args) != 2 || args[1] != "enroll" {
			return errors.New("usage: wardkey approval enroll")
		}
		return enrollApproval(out)

	case "serve":
		if len(args) != 1 {
			return errors.New("'serve' does not accept additional arguments")
		}

		home, err := config.DefaultHome()
		if err != nil {
			return fmt.Errorf("resolve Wardkey home: %w", err)
		}

		if home.Development {
			if _, err := fmt.Fprintln(out, home.Warning); err != nil {
				return err
			}
		}

		policyPath := filepath.Join(home.Path, "policy.json")
		rules, err := config.LoadPolicy(policyPath)
		if err != nil {
			return fmt.Errorf("load Wardkey policy: %w", err)
		}

		vaultPath := filepath.Join(home.Path, "vault.wkv")
		entries, auditKey, approvalKey, vaultExists, err := loadVaultForServeWithKeys(vaultPath)
		if err != nil {
			return err
		}

		auditLogger, err := audit.NewLogger(filepath.Join(home.Path, "audit.jsonl"))
		if err != nil {
			clearCredentialEntries(entries)
			clear(auditKey)
			clear(approvalKey)
			return fmt.Errorf("prepare audit log: %w", err)
		}

		handler := broker.NewHandler(rules, broker.CredentialExecutor)
		// Clear session memory and retained keys on every return path.
		defer handler.Close()

		enrollmentStore, err := approval.NewStore(filepath.Join(home.Path, "approval.json"))
		if err != nil {
			clearCredentialEntries(entries)
			clear(auditKey)
			clear(approvalKey)
			return fmt.Errorf("prepare Windows Hello approval store: %w", err)
		}
		if err := handler.SetWindowsHelloApprovalStore(enrollmentStore); err != nil {
			clearCredentialEntries(entries)
			clear(auditKey)
			clear(approvalKey)
			return fmt.Errorf("configure Windows Hello approval: %w", err)
		}

		if err := handler.SetAuditLogger(auditLogger); err != nil {
			clearCredentialEntries(entries)
			clear(auditKey)
			clear(approvalKey)
			return fmt.Errorf("configure broker audit log: %w", err)
		}

		if vaultExists {
			if err := handler.UnlockWithKeys(entries, auditKey, approvalKey); err != nil {
				clearCredentialEntries(entries)
				clear(auditKey)
				clear(approvalKey)
				return fmt.Errorf("unlock broker session: %w", err)
			}
			if _, err := fmt.Fprintln(out, "Vault unlocked for this broker session."); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintln(out, "No vault found; broker will remain locked."); err != nil {
				return err
			}
		}

		if _, err := fmt.Fprintln(
			out,
			"Starting the local broker. Git and AWS credential responses are available only when policy allows the request. Press Ctrl+C to stop.",
		); err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		return broker.Serve(ctx, handler)

	case "status":
		if len(args) != 1 {
			return errors.New("'status' does not accept additional arguments")
		}
		return showStatus(out)

	case "lock":
		if len(args) != 1 {
			return errors.New("'lock' does not accept additional arguments")
		}
		return lockBroker(out)

	case "fingerprint":
		return showFingerprint(args, out)

	default:
		return fmt.Errorf("unknown command %q; run 'wardkey help'", args[0])
	}
}

// loadVaultForServe preserves the existing helper API for tests and callers
// that only need the entries and audit key.
func loadVaultForServe(path string) ([]vault.Entry, []byte, bool, error) {
	entries, auditKey, approvalKey, exists, err := loadVaultForServeWithKeys(path)
	clear(approvalKey)
	return entries, auditKey, exists, err
}

// loadVaultForServeWithKeys prompts locally for the passphrase when a vault
// exists. It never sends the passphrase over IPC.
func loadVaultForServeWithKeys(path string) ([]vault.Entry, []byte, []byte, bool, error) {
	_, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil, false, nil
		}
		return nil, nil, nil, false, fmt.Errorf("inspect vault path: %w", err)
	}

	passphrase, err := readPassphrase("Unlock vault passphrase: ")
	if err != nil {
		return nil, nil, nil, true, err
	}
	defer clear(passphrase)

	entries, auditKey, approvalKey, err := vault.LoadWithSessionKeys(path, passphrase)
	if err != nil {
		return nil, nil, nil, true, fmt.Errorf("unlock vault: %w", err)
	}

	auditPath := filepath.Join(filepath.Dir(path), "audit.jsonl")
	if err := recordVaultUnlock(auditPath, auditKey); err != nil {
		clearCredentialEntries(entries)
		clear(auditKey)
		clear(approvalKey)
		return nil, nil, nil, true, fmt.Errorf("initialize audit log: %w", err)
	}

	return entries, auditKey, approvalKey, true, nil
}

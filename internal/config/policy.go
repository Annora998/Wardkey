package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"

	"wardkey/internal/policy"
	"wardkey/internal/vault"
)

const maxPolicyFileBytes = 1 << 20 // 1 MiB

// LoadPolicy loads a validated policy from an ACL-protected file.
// If the file does not exist, it returns an empty policy that denies all
// credential requests.
func LoadPolicy(path string) (policy.Policy, error) {
	if path == "" {
		return policy.Policy{}, errors.New("policy path is required")
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return policy.Policy{}, fmt.Errorf("resolve policy path: %w", err)
	}

	if err := vault.EnsurePrivateDirectory(filepath.Dir(absolute)); err != nil {
		return policy.Policy{}, fmt.Errorf("protect policy directory: %w", err)
	}
	if err := vault.CheckStorageFilesystem(absolute); err != nil {
		return policy.Policy{}, fmt.Errorf("policy filesystem check failed: %w", err)
	}
	if err := vault.RestrictExistingPrivateFile(absolute); err != nil {
		return policy.Policy{}, fmt.Errorf("protect policy file: %w", err)
	}

	file, err := os.Open(absolute)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return policy.Policy{Version: 1}, nil
		}
		return policy.Policy{}, fmt.Errorf("open policy file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return policy.Policy{}, fmt.Errorf("inspect policy file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return policy.Policy{}, errors.New("policy path is not a regular file")
	}
	if info.Size() > maxPolicyFileBytes {
		return policy.Policy{}, errors.New("policy file exceeds the 1 MiB limit")
	}

	data, err := io.ReadAll(io.LimitReader(file, maxPolicyFileBytes+1))
	if err != nil {
		return policy.Policy{}, fmt.Errorf("read policy file: %w", err)
	}
	if len(data) > maxPolicyFileBytes {
		return policy.Policy{}, errors.New("policy file exceeds the 1 MiB limit")
	}
	if !utf8.Valid(data) {
		return policy.Policy{}, errors.New("policy file is not valid UTF-8")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var loaded policy.Policy
	if err := decoder.Decode(&loaded); err != nil {
		return policy.Policy{}, fmt.Errorf("decode policy file: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return policy.Policy{}, errors.New("policy file contains trailing JSON data")
		}
		return policy.Policy{}, fmt.Errorf("check policy file ending: %w", err)
	}

	if err := policy.Validate(loaded); err != nil {
		return policy.Policy{}, fmt.Errorf("validate policy file: %w", err)
	}

	return loaded, nil
}

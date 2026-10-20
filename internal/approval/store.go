package approval

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"wardkey/internal/vault"
)

const (
	enrollmentVersion = 1
	maxEnrollmentSize = 4096
	enrollmentMACInfo = "wardkey/webauthn/enrollment/hmac-sha256/v1\x00"
)

var (
	ErrNotEnrolled       = errors.New("Windows Hello approval is not enrolled")
	ErrInvalidEnrollment = errors.New("invalid Windows Hello enrollment record")
	ErrEnrollmentMAC     = errors.New("Windows Hello enrollment authentication failed")
)

// Enrollment contains the public data needed to verify an authenticator
// assertion. It contains no private credential key.
type Enrollment struct {
	Version      int    `json:"version"`
	RPID         string `json:"rp_id"`
	CredentialID []byte `json:"credential_id"`
	PublicKeyX   []byte `json:"public_key_x"`
	PublicKeyY   []byte `json:"public_key_y"`
}

type storedEnrollment struct {
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}

// Store reads and writes the authenticated enrollment file.
type Store struct {
	path string
}

// NewStore creates a store handle for path. It does not read or create files.
func NewStore(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("approval enrollment path is required")
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve approval enrollment path: %w", err)
	}

	return &Store{path: absolute}, nil
}

// Load reads and authenticates the enrollment record. The caller must use
// the returned data only for verification and must not modify it.
func (s *Store) Load(approvalKey []byte) (Enrollment, error) {
	if s == nil || s.path == "" {
		return Enrollment{}, errors.New("approval enrollment store is unavailable")
	}
	if len(approvalKey) != vault.ApprovalKeySize {
		return Enrollment{}, errors.New("invalid approval enrollment key")
	}

	info, err := os.Lstat(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Enrollment{}, ErrNotEnrolled
		}
		return Enrollment{}, fmt.Errorf("inspect approval enrollment file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Enrollment{}, ErrInvalidEnrollment
	}

	if err := vault.RestrictExistingPrivateFile(s.path); err != nil {
		return Enrollment{}, fmt.Errorf("secure approval enrollment file: %w", err)
	}

	file, err := os.Open(s.path)
	if err != nil {
		return Enrollment{}, fmt.Errorf("open approval enrollment file: %w", err)
	}
	defer file.Close()

	info, err = file.Stat()
	if err != nil {
		return Enrollment{}, fmt.Errorf("inspect open approval enrollment file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxEnrollmentSize {
		return Enrollment{}, ErrInvalidEnrollment
	}

	data, err := io.ReadAll(io.LimitReader(file, maxEnrollmentSize+1))
	if err != nil {
		return Enrollment{}, fmt.Errorf("read approval enrollment file: %w", err)
	}
	if len(data) == 0 || len(data) > maxEnrollmentSize {
		return Enrollment{}, ErrInvalidEnrollment
	}

	return decodeEnrollment(data, approvalKey)
}

// Create writes the first enrollment and refuses to replace an existing file.
func (s *Store) Create(enrollment Enrollment, approvalKey []byte) error {
	if s == nil || s.path == "" {
		return errors.New("approval enrollment store is unavailable")
	}
	data, err := encodeEnrollment(enrollment, approvalKey)
	if err != nil {
		return err
	}

	if err := vault.CreatePrivateFileAtomically(s.path, data); err != nil {
		return fmt.Errorf("create approval enrollment: %w", err)
	}
	return nil
}

// Replace atomically replaces the enrollment record. The caller must first
// verify the existing credential with user verification before allowing this.
func (s *Store) Replace(enrollment Enrollment, approvalKey []byte) error {
	if s == nil || s.path == "" {
		return errors.New("approval enrollment store is unavailable")
	}
	data, err := encodeEnrollment(enrollment, approvalKey)
	if err != nil {
		return err
	}

	if err := vault.ReplacePrivateFileAtomically(s.path, data); err != nil {
		return fmt.Errorf("replace approval enrollment: %w", err)
	}
	return nil
}

func encodeEnrollment(enrollment Enrollment, approvalKey []byte) ([]byte, error) {
	if len(approvalKey) != vault.ApprovalKeySize {
		return nil, errors.New("invalid approval enrollment key")
	}
	if err := validateEnrollment(enrollment); err != nil {
		return nil, err
	}

	payload, err := json.Marshal(enrollment)
	if err != nil {
		return nil, fmt.Errorf("encode approval enrollment: %w", err)
	}

	mac := enrollmentMAC(approvalKey, payload)
	record, err := json.Marshal(storedEnrollment{
		Payload: payload,
		MAC:     hex.EncodeToString(mac),
	})
	clear(mac)
	if err != nil {
		return nil, fmt.Errorf("encode authenticated approval enrollment: %w", err)
	}
	if len(record) == 0 || len(record) > maxEnrollmentSize {
		clear(record)
		return nil, ErrInvalidEnrollment
	}

	return record, nil
}

func decodeEnrollment(data, approvalKey []byte) (Enrollment, error) {
	if len(approvalKey) != vault.ApprovalKeySize {
		return Enrollment{}, errors.New("invalid approval enrollment key")
	}

	var record storedEnrollment
	if err := decodeStrictJSON(data, &record); err != nil {
		return Enrollment{}, fmt.Errorf("%w: decode record", ErrInvalidEnrollment)
	}
	if len(record.Payload) == 0 {
		return Enrollment{}, ErrInvalidEnrollment
	}

	gotMAC, err := hex.DecodeString(record.MAC)
	if err != nil || len(gotMAC) != sha256.Size {
		return Enrollment{}, ErrEnrollmentMAC
	}
	wantMAC := enrollmentMAC(approvalKey, record.Payload)
	macValid := hmac.Equal(gotMAC, wantMAC)
	clear(gotMAC)
	clear(wantMAC)
	if !macValid {
		return Enrollment{}, ErrEnrollmentMAC
	}

	var enrollment Enrollment
	if err := decodeStrictJSON(record.Payload, &enrollment); err != nil {
		return Enrollment{}, fmt.Errorf("%w: decode payload", ErrInvalidEnrollment)
	}

	canonicalPayload, err := json.Marshal(enrollment)
	if err != nil {
		return Enrollment{}, fmt.Errorf("%w: encode payload", ErrInvalidEnrollment)
	}
	canonical := bytes.Equal(canonicalPayload, record.Payload)
	clear(canonicalPayload)
	if !canonical {
		return Enrollment{}, ErrInvalidEnrollment
	}

	if err := validateEnrollment(enrollment); err != nil {
		return Enrollment{}, err
	}
	return enrollment, nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func enrollmentMAC(approvalKey, payload []byte) []byte {
	mac := hmac.New(sha256.New, approvalKey)
	_, _ = mac.Write([]byte(enrollmentMACInfo))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func validateEnrollment(enrollment Enrollment) error {
	if enrollment.Version != enrollmentVersion ||
		strings.TrimSpace(enrollment.RPID) == "" ||
		enrollment.RPID != strings.TrimSpace(enrollment.RPID) ||
		len(enrollment.RPID) > 253 ||
		len(enrollment.CredentialID) == 0 ||
		len(enrollment.CredentialID) > 1024 ||
		len(enrollment.PublicKeyX) != 32 ||
		len(enrollment.PublicKeyY) != 32 {
		return ErrInvalidEnrollment
	}

	x := new(big.Int).SetBytes(enrollment.PublicKeyX)
	y := new(big.Int).SetBytes(enrollment.PublicKeyY)
	if !elliptic.P256().IsOnCurve(x, y) {
		return ErrInvalidEnrollment
	}

	return nil
}

package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestSealAndOpen(t *testing.T) {
	passphrase := []byte("dummy test passphrase")
	plaintext := []byte(`{"entries":[]}`)

	blob, err := Seal(passphrase, plaintext)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if got := binary.LittleEndian.Uint16(blob[versionOffset : versionOffset+2]); got != formatVersion {
		t.Fatalf("Seal() version = %d, want %d", got, formatVersion)
	}

	got, err := Open(passphrase, blob)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open() = %q, want %q", got, plaintext)
	}
}

func TestOpenReadsLegacyVersionOneVault(t *testing.T) {
	passphrase := []byte("dummy legacy test passphrase")
	plaintext := []byte(`{"entries":[{"provider":"generic"}]}`)

	blob, err := sealLegacyV1ForTest(passphrase, plaintext)
	if err != nil {
		t.Fatalf("sealLegacyV1ForTest() error = %v", err)
	}

	got, err := Open(passphrase, blob)
	if err != nil {
		t.Fatalf("Open() legacy vault error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open() = %q, want %q", got, plaintext)
	}
}

func TestOpenRejectsWrongPassphrase(t *testing.T) {
	blob, err := Seal([]byte("dummy correct passphrase"), []byte("test payload"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	_, err = Open([]byte("dummy incorrect passphrase"), blob)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Open() error = %v, want ErrAuthentication", err)
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	blob, err := Seal([]byte("dummy test passphrase"), []byte("test payload"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	blob[headerSize] ^= 0x01

	_, err = Open([]byte("dummy test passphrase"), blob)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Open() error = %v, want ErrAuthentication", err)
	}
}

func TestOpenRejectsTamperedWrappedKey(t *testing.T) {
	blob, err := Seal([]byte("dummy test passphrase"), []byte("test payload"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	blob[wrappedKeyOffset] ^= 0x01

	_, err = Open([]byte("dummy test passphrase"), blob)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Open() error = %v, want ErrAuthentication", err)
	}
}

func TestOpenRejectsInvalidHeader(t *testing.T) {
	blob, err := Seal([]byte("dummy test passphrase"), []byte("test payload"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	blob[0] ^= 0x01

	_, err = Open([]byte("dummy test passphrase"), blob)
	if !errors.Is(err, ErrInvalidVault) {
		t.Fatalf("Open() error = %v, want ErrInvalidVault", err)
	}
}

func TestOpenRejectsUnsupportedVersion(t *testing.T) {
	blob, err := Seal([]byte("dummy test passphrase"), []byte("test payload"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	binary.LittleEndian.PutUint16(blob[versionOffset:versionOffset+2], 99)

	_, err = Open([]byte("dummy test passphrase"), blob)
	if !errors.Is(err, ErrInvalidVault) {
		t.Fatalf("Open() error = %v, want ErrInvalidVault", err)
	}
}

func TestSealAndOpenRequirePassphraseLength(t *testing.T) {
	if _, err := Seal([]byte("short"), []byte("payload")); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("Seal() error = %v, want ErrWeakPassphrase", err)
	}

	if _, err := Open([]byte("short"), []byte("not a vault")); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("Open() error = %v, want ErrWeakPassphrase", err)
	}
}

func TestOpenRejectsTruncatedVault(t *testing.T) {
	_, err := Open([]byte("dummy test passphrase"), []byte("short"))
	if !errors.Is(err, ErrInvalidVault) {
		t.Fatalf("Open() error = %v, want ErrInvalidVault", err)
	}
}

func sealLegacyV1ForTest(passphrase, plaintext []byte) ([]byte, error) {
	header := make([]byte, legacyHeaderSize)
	copy(header[:len(magic)], magic[:])
	binary.LittleEndian.PutUint16(header[versionOffset:versionOffset+2], legacyFormatVersion)
	binary.LittleEndian.PutUint32(header[kdfTimeOffset:kdfTimeOffset+4], kdfTime)
	binary.LittleEndian.PutUint32(header[kdfMemoryOffset:kdfMemoryOffset+4], kdfMemoryKiB)
	header[kdfParallelismOffset] = kdfParallelism

	salt := header[saltOffset : saltOffset+saltSize]
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	nonce := header[legacyNonceOffset : legacyNonceOffset+nonceSize]
	for i := range nonce {
		nonce[i] = byte(0x80 + i)
	}

	key := argon2.IDKey(
		passphrase,
		salt,
		kdfTime,
		kdfMemoryKiB,
		kdfParallelism,
		chacha20poly1305.KeySize,
	)
	defer zero(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, header)
	blob := make([]byte, 0, len(header)+len(ciphertext))
	blob = append(blob, header...)
	blob = append(blob, ciphertext...)
	return blob, nil
}

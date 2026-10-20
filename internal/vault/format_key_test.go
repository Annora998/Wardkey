package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestOpenWithDataKeyReturnsVersionTwoKey(t *testing.T) {
	passphrase := []byte("dummy version two passphrase")
	wantPlaintext := []byte(`{"entries":[]}`)

	blob, err := Seal(passphrase, wantPlaintext)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	gotPlaintext, dataKey, err := OpenWithDataKey(passphrase, blob)
	if err != nil {
		t.Fatalf("OpenWithDataKey() error = %v", err)
	}
	defer zero(gotPlaintext)
	defer zero(dataKey)

	if !bytes.Equal(gotPlaintext, wantPlaintext) {
		t.Fatalf("plaintext = %q, want %q", gotPlaintext, wantPlaintext)
	}
	if len(dataKey) != chacha20poly1305.KeySize {
		t.Fatalf("data key length = %d, want %d", len(dataKey), chacha20poly1305.KeySize)
	}
	if bytes.Equal(dataKey, make([]byte, chacha20poly1305.KeySize)) {
		t.Fatal("OpenWithDataKey() returned an all-zero data key")
	}
}

func TestOpenWithDataKeyRejectsWrongPassphrase(t *testing.T) {
	blob, err := Seal(
		[]byte("dummy correct version two passphrase"),
		[]byte(`{"entries":[]}`),
	)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	plaintext, dataKey, err := OpenWithDataKey(
		[]byte("dummy incorrect version two passphrase"),
		blob,
	)
	if err == nil {
		zero(plaintext)
		zero(dataKey)
		t.Fatal("OpenWithDataKey() accepted an incorrect passphrase")
	}
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("OpenWithDataKey() error = %v, want ErrAuthentication", err)
	}
}

func TestOpenWithDataKeyRejectsLegacyVaultButOpenStillReadsIt(t *testing.T) {
	passphrase := []byte("dummy legacy version one passphrase")
	wantPlaintext := []byte(`{"entries":[]}`)
	blob := makeLegacyFormatTestBlob(t, passphrase, wantPlaintext)

	plaintext, dataKey, err := OpenWithDataKey(passphrase, blob)
	if err == nil {
		zero(plaintext)
		zero(dataKey)
		t.Fatal("OpenWithDataKey() accepted a version 1 vault")
	}
	if !errors.Is(err, ErrDataKeyUnavailable) {
		t.Fatalf("OpenWithDataKey() error = %v, want ErrDataKeyUnavailable", err)
	}

	gotPlaintext, err := Open(passphrase, blob)
	if err != nil {
		t.Fatalf("Open() failed to read version 1 vault: %v", err)
	}
	defer zero(gotPlaintext)

	if !bytes.Equal(gotPlaintext, wantPlaintext) {
		t.Fatalf("Open() plaintext = %q, want %q", gotPlaintext, wantPlaintext)
	}
}

func makeLegacyFormatTestBlob(t *testing.T, passphrase, plaintext []byte) []byte {
	t.Helper()

	header := make([]byte, legacyHeaderSize)
	copy(header[:len(magic)], magic[:])
	binary.LittleEndian.PutUint16(
		header[versionOffset:versionOffset+2],
		legacyFormatVersion,
	)
	binary.LittleEndian.PutUint32(
		header[kdfTimeOffset:kdfTimeOffset+4],
		kdfTime,
	)
	binary.LittleEndian.PutUint32(
		header[kdfMemoryOffset:kdfMemoryOffset+4],
		kdfMemoryKiB,
	)
	header[kdfParallelismOffset] = kdfParallelism

	salt := header[saltOffset : saltOffset+saltSize]
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate legacy test salt: %v", err)
	}

	nonce := header[legacyNonceOffset : legacyNonceOffset+nonceSize]
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate legacy test nonce: %v", err)
	}

	key := deriveKey(passphrase, salt)
	defer zero(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("initialize legacy test encryption: %v", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, header)
	return append(header, ciphertext...)
}

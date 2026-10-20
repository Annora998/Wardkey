package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	legacyFormatVersion uint16 = 1
	formatVersion       uint16 = 2

	kdfTime        uint32 = 3
	kdfMemoryKiB   uint32 = 64 * 1024
	kdfParallelism        = 4

	saltSize       = 32
	nonceSize      = chacha20poly1305.NonceSizeX
	wrappedKeySize = chacha20poly1305.KeySize + chacha20poly1305.Overhead

	versionOffset        = 8
	kdfTimeOffset        = 10
	kdfMemoryOffset      = 14
	kdfParallelismOffset = 18
	saltOffset           = 19

	legacyNonceOffset = saltOffset + saltSize
	legacyHeaderSize  = legacyNonceOffset + nonceSize

	wrapNonceOffset    = saltOffset + saltSize
	wrappedKeyOffset   = wrapNonceOffset + nonceSize
	payloadNonceOffset = wrappedKeyOffset + wrappedKeySize
	wrapAADSize        = wrapNonceOffset + nonceSize
	headerSize         = payloadNonceOffset + nonceSize

	MaxVaultSize       = 16 << 20
	minPassphraseBytes = 12
)

var (
	ErrInvalidVault       = errors.New("invalid vault format")
	ErrAuthentication     = errors.New("vault authentication failed")
	ErrWeakPassphrase     = errors.New("passphrase must be at least 12 bytes")
	ErrVaultTooLarge      = errors.New("vault exceeds maximum size")
	ErrDataKeyUnavailable = errors.New("vault has no version 2 data key; migrate it first")
)

var magic = [8]byte{'W', 'A', 'R', 'D', 'K', 'E', 'Y', '1'}

// Seal encrypts plaintext into a version 2 vault envelope using a new random
// data-encryption key. The caller remains responsible for clearing plaintext
// and passphrase buffers.
func Seal(passphrase, plaintext []byte) ([]byte, error) {
	if len(passphrase) < minPassphraseBytes {
		return nil, ErrWeakPassphrase
	}

	dataKey := make([]byte, chacha20poly1305.KeySize)
	defer zero(dataKey)

	if _, err := rand.Read(dataKey); err != nil {
		return nil, fmt.Errorf("generate vault data key: %w", err)
	}

	return SealWithDataKey(passphrase, plaintext, dataKey)
}

// SealWithDataKey encrypts plaintext into a version 2 vault envelope using
// the supplied data-encryption key. It generates fresh salt and nonces, so
// callers can safely update vault contents while retaining the same data key.
// The caller owns dataKey and remains responsible for clearing it.
func SealWithDataKey(passphrase, plaintext, dataKey []byte) ([]byte, error) {
	if len(passphrase) < minPassphraseBytes {
		return nil, ErrWeakPassphrase
	}
	if len(dataKey) != chacha20poly1305.KeySize {
		return nil, ErrInvalidDataKey
	}
	if len(plaintext) > MaxVaultSize-headerSize-chacha20poly1305.Overhead {
		return nil, ErrVaultTooLarge
	}

	header := make([]byte, headerSize)
	copy(header[:len(magic)], magic[:])
	binary.LittleEndian.PutUint16(header[versionOffset:versionOffset+2], formatVersion)
	binary.LittleEndian.PutUint32(header[kdfTimeOffset:kdfTimeOffset+4], kdfTime)
	binary.LittleEndian.PutUint32(header[kdfMemoryOffset:kdfMemoryOffset+4], kdfMemoryKiB)
	header[kdfParallelismOffset] = kdfParallelism

	salt := header[saltOffset : saltOffset+saltSize]
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate vault salt: %w", err)
	}

	wrapNonce := header[wrapNonceOffset : wrapNonceOffset+nonceSize]
	if _, err := rand.Read(wrapNonce); err != nil {
		return nil, fmt.Errorf("generate vault key-wrapping nonce: %w", err)
	}

	payloadNonce := header[payloadNonceOffset : payloadNonceOffset+nonceSize]
	if _, err := rand.Read(payloadNonce); err != nil {
		return nil, fmt.Errorf("generate vault payload nonce: %w", err)
	}

	wrappingKey := deriveKey(passphrase, salt)
	defer zero(wrappingKey)

	wrappingAEAD, err := chacha20poly1305.NewX(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("initialize vault key wrapping: %w", err)
	}

	wrappedKey := wrappingAEAD.Seal(nil, wrapNonce, dataKey, header[:wrapAADSize])
	defer zero(wrappedKey)
	if len(wrappedKey) != wrappedKeySize {
		return nil, ErrInvalidVault
	}
	copy(header[wrappedKeyOffset:wrappedKeyOffset+wrappedKeySize], wrappedKey)

	payloadAEAD, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, fmt.Errorf("initialize vault encryption: %w", err)
	}

	ciphertext := payloadAEAD.Seal(nil, payloadNonce, plaintext, header)
	result := make([]byte, 0, len(header)+len(ciphertext))
	result = append(result, header...)
	result = append(result, ciphertext...)
	return result, nil
}

// Open authenticates and decrypts a version 1 or version 2 vault envelope.
// Version 1 remains readable so existing vaults can be migrated by saving them.
func Open(passphrase, blob []byte) ([]byte, error) {
	if len(passphrase) < minPassphraseBytes {
		return nil, ErrWeakPassphrase
	}
	if len(blob) > MaxVaultSize {
		return nil, ErrVaultTooLarge
	}
	if len(blob) < versionOffset+2 || !bytes.Equal(blob[:len(magic)], magic[:]) {
		return nil, ErrInvalidVault
	}

	version := binary.LittleEndian.Uint16(blob[versionOffset : versionOffset+2])
	switch version {
	case legacyFormatVersion:
		return openVersionOne(passphrase, blob)
	case formatVersion:
		return openVersionTwo(passphrase, blob)
	default:
		return nil, ErrInvalidVault
	}
}

// OpenWithDataKey authenticates and decrypts a version 2 vault, returning the
// unwrapped random data key to the caller. The caller owns both returned byte
// slices and must clear them when finished. Version 1 vaults do not contain a
// random data key and return ErrDataKeyUnavailable.
func OpenWithDataKey(passphrase, blob []byte) (plaintext, dataKey []byte, err error) {
	if len(passphrase) < minPassphraseBytes {
		return nil, nil, ErrWeakPassphrase
	}
	if len(blob) > MaxVaultSize {
		return nil, nil, ErrVaultTooLarge
	}
	if len(blob) < versionOffset+2 || !bytes.Equal(blob[:len(magic)], magic[:]) {
		return nil, nil, ErrInvalidVault
	}

	version := binary.LittleEndian.Uint16(blob[versionOffset : versionOffset+2])
	switch version {
	case legacyFormatVersion:
		return nil, nil, ErrDataKeyUnavailable
	case formatVersion:
		return openVersionTwoWithDataKey(passphrase, blob)
	default:
		return nil, nil, ErrInvalidVault
	}
}

func openVersionOne(passphrase, blob []byte) ([]byte, error) {
	if len(blob) < legacyHeaderSize+chacha20poly1305.Overhead {
		return nil, ErrInvalidVault
	}

	header := blob[:legacyHeaderSize]
	if !validHeader(header, legacyFormatVersion) {
		return nil, ErrInvalidVault
	}

	salt := header[saltOffset : saltOffset+saltSize]
	nonce := header[legacyNonceOffset : legacyNonceOffset+nonceSize]

	key := deriveKey(passphrase, salt)
	defer zero(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("initialize legacy vault decryption: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, blob[legacyHeaderSize:], header)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func openVersionTwo(passphrase, blob []byte) ([]byte, error) {
	plaintext, dataKey, err := openVersionTwoWithDataKey(passphrase, blob)
	if err != nil {
		return nil, err
	}
	zero(dataKey)
	return plaintext, nil
}

func openVersionTwoWithDataKey(passphrase, blob []byte) ([]byte, []byte, error) {
	if len(blob) < headerSize+chacha20poly1305.Overhead {
		return nil, nil, ErrInvalidVault
	}

	header := blob[:headerSize]
	if !validHeader(header, formatVersion) {
		return nil, nil, ErrInvalidVault
	}

	salt := header[saltOffset : saltOffset+saltSize]
	wrapNonce := header[wrapNonceOffset : wrapNonceOffset+nonceSize]
	wrappedKey := header[wrappedKeyOffset : wrappedKeyOffset+wrappedKeySize]
	payloadNonce := header[payloadNonceOffset : payloadNonceOffset+nonceSize]

	wrappingKey := deriveKey(passphrase, salt)
	defer zero(wrappingKey)

	wrappingAEAD, err := chacha20poly1305.NewX(wrappingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize vault key unwrapping: %w", err)
	}

	dataKey, err := wrappingAEAD.Open(
		nil,
		wrapNonce,
		wrappedKey,
		header[:wrapAADSize],
	)
	if err != nil {
		return nil, nil, ErrAuthentication
	}

	if len(dataKey) != chacha20poly1305.KeySize {
		zero(dataKey)
		return nil, nil, ErrInvalidVault
	}

	payloadAEAD, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		zero(dataKey)
		return nil, nil, fmt.Errorf("initialize vault decryption: %w", err)
	}

	plaintext, err := payloadAEAD.Open(nil, payloadNonce, blob[headerSize:], header)
	if err != nil {
		zero(dataKey)
		return nil, nil, ErrAuthentication
	}

	return plaintext, dataKey, nil
}

func validHeader(header []byte, expectedVersion uint16) bool {
	if len(header) < saltOffset+saltSize {
		return false
	}

	return bytes.Equal(header[:len(magic)], magic[:]) &&
		binary.LittleEndian.Uint16(header[versionOffset:versionOffset+2]) == expectedVersion &&
		binary.LittleEndian.Uint32(header[kdfTimeOffset:kdfTimeOffset+4]) == kdfTime &&
		binary.LittleEndian.Uint32(header[kdfMemoryOffset:kdfMemoryOffset+4]) == kdfMemoryKiB &&
		header[kdfParallelismOffset] == kdfParallelism
}

func deriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(
		passphrase,
		salt,
		kdfTime,
		kdfMemoryKiB,
		kdfParallelism,
		chacha20poly1305.KeySize,
	)
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
	runtime.KeepAlive(value)
}

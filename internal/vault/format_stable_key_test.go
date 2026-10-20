package vault

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestSealWithDataKeyPreservesDataKey(t *testing.T) {
	passphrase := []byte("dummy stable data key test passphrase")
	plaintext := []byte(`{"entries":[]}`)

	dataKey := make([]byte, chacha20poly1305.KeySize)
	for i := range dataKey {
		dataKey[i] = byte(i + 1)
	}
	defer zero(dataKey)

	blob, err := SealWithDataKey(passphrase, plaintext, dataKey)
	if err != nil {
		t.Fatalf("SealWithDataKey() error = %v", err)
	}

	gotPlaintext, gotDataKey, err := OpenWithDataKey(passphrase, blob)
	if err != nil {
		t.Fatalf("OpenWithDataKey() error = %v", err)
	}
	defer zero(gotPlaintext)
	defer zero(gotDataKey)

	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("plaintext = %q, want %q", gotPlaintext, plaintext)
	}
	if !bytes.Equal(gotDataKey, dataKey) {
		t.Fatal("opened vault did not preserve the supplied data key")
	}
}

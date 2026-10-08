package browser

import (
	"crypto/aes"
	"crypto/cipher"
	"os"
	"path/filepath"
	"testing"
)

func TestDecryptValueAESGCM(t *testing.T) {
	t.Parallel()

	key := []byte("0123456789abcdef0123456789abcdef")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM() error = %v", err)
	}
	nonce := []byte("0123456789ab")
	plaintext := []byte("session-value")
	encrypted := append([]byte("v10"), nonce...)
	encrypted = gcm.Seal(encrypted, nonce, plaintext, nil)

	got, err := decryptValue(encrypted, key)
	if err != nil {
		t.Fatalf("decryptValue() error = %v", err)
	}
	if got != string(plaintext) {
		t.Fatalf("decryptValue() = %q, want %q", got, plaintext)
	}
}

func TestDecryptValueRejectsTruncatedAESPayloadWithoutPanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("decryptValue() panicked: %v", recovered)
		}
	}()
	_, _ = decryptValue([]byte("v10short"), []byte("0123456789abcdef0123456789abcdef"))
}

func TestGetAESKeyRejectsMalformedLocalState(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing os_crypt": `{}`,
		"invalid base64":   `{"os_crypt":{"encrypted_key":"not base64"}}`,
		"short key":        `{"os_crypt":{"encrypted_key":"S0VZ"}}`,
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "Local State")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatalf("write Local State: %v", err)
			}
			if _, err := getAESKey(path); err == nil {
				t.Fatal("getAESKey() error = nil, want malformed input error")
			}
		})
	}
}

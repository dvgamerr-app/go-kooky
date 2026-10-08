package browser

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// ErrAppBoundEncryption is returned when cookies are protected by Chromium's
// App-Bound Encryption (v20 prefix), which this library deliberately does not
// implement. Chrome, Edge and Brave on current Windows releases use it; use a
// Firefox-family browser instead.
var ErrAppBoundEncryption = errors.New("cookies use Chromium App-Bound Encryption (v20), which is not supported; use a Firefox-family browser")

var TEMP_DIR string

// DecryptFailedPlaceholder is the sentinel Cookie.Value set when a cookie's
// encrypted_value could not be decrypted (e.g. an unsupported scheme such as
// Chromium's v20 App-Bound Encryption). Callers can compare against it to
// report decrypt success/failure without ever handling the raw bytes.
const DecryptFailedPlaceholder = "[DECRYPT FAILED]"

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	TEMP_DIR = filepath.Join(os.TempDir(), ".kooky")
	if err := os.MkdirAll(TEMP_DIR, 0o755); err != nil {
		panic(err)
	}
}

type Cookie struct {
	Host          string
	Name          string
	Value         string
	Path          string
	ExpiresUTC    int64
	IsSecure      bool
	IsHttpOnly    bool
	CreationUTC   int64
	LastAccessUTC int64
	// Expires is ExpiresUTC converted to a time.Time; zero for session cookies.
	Expires time.Time

	// decryptErr records why Value is DecryptFailedPlaceholder.
	decryptErr error
}

// Decrypted reports whether Value holds a real cookie value rather than the
// DecryptFailedPlaceholder sentinel.
func (c Cookie) Decrypted() bool { return c.Value != DecryptFailedPlaceholder }

// MatchesHost reports whether the cookie applies to host using cookie-jar
// domain rules: a cookie for ".example.com" applies to "api.example.com".
func (c Cookie) MatchesHost(host string) bool {
	h := strings.ToLower(strings.TrimPrefix(c.Host, "."))
	host = strings.ToLower(strings.TrimPrefix(host, "."))
	return h != "" && (host == h || strings.HasSuffix(host, "."+h))
}

// HTTPCookie converts the cookie to a net/http cookie.
func (c Cookie) HTTPCookie() *http.Cookie {
	return &http.Cookie{
		Name:     c.Name,
		Value:    c.Value,
		Domain:   c.Host,
		Path:     c.Path,
		Expires:  c.Expires,
		Secure:   c.IsSecure,
		HttpOnly: c.IsHttpOnly,
	}
}

// chromiumExpires converts a Chromium expires_utc (microseconds since
// 1601-01-01) to a time.Time; 0 means a session cookie.
func chromiumExpires(us int64) time.Time {
	if us <= 0 {
		return time.Time{}
	}
	// Go through Unix seconds: us*1000 as a time.Duration overflows int64 for
	// dates this far from the 1601 epoch.
	const epochDiffSeconds = 11644473600 // 1601-01-01 to 1970-01-01
	return time.Unix(us/1_000_000-epochDiffSeconds, (us%1_000_000)*1000).UTC()
}

// firefoxExpires converts a moz_cookies expiry to a time.Time. Older Firefox
// releases store seconds and newer ones milliseconds, so the unit is inferred
// from the magnitude.
func firefoxExpires(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	if v > 1e11 {
		return time.UnixMilli(v).UTC()
	}
	return time.Unix(v, 0).UTC()
}

// getAESKey อ่าน encryption key จาก Local State file
func getAESKey(localStatePath string) ([]byte, error) {
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	var localState struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, err
	}
	if localState.OSCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("os_crypt.encrypted_key is missing")
	}

	decodedKey, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}

	// ตัด "DPAPI" prefix (5 bytes แรก)
	if len(decodedKey) < len("DPAPI") {
		return nil, fmt.Errorf("encrypted key is shorter than the DPAPI prefix")
	}
	decodedKey = decodedKey[5:]

	if runtime.GOOS == "windows" {
		// Decrypt ด้วย DPAPI
		key, err := decrypt(decodedKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	} else {
		// สำหรับ OS อื่น assume ไม่ encrypt อีก (ไม่ถูกต้อง แต่สำหรับ demo)
		return decodedKey, nil
	}
}

// decryptValue decrypt cookie value
func decryptValue(encryptedValue []byte, key []byte) (string, error) {
	if len(encryptedValue) == 0 {
		return "", nil
	}
	if bytes.HasPrefix(encryptedValue, []byte("v20")) {
		return "", ErrAppBoundEncryption
	}

	// Try AES if key is available and looks like v10/v11
	if key != nil && len(encryptedValue) > 3 && encryptedValue[0] == 'v' && encryptedValue[1] == '1' {
		// ตัด prefix "v10" หรือ "v11" (3 bytes)
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		payload := encryptedValue[3:]
		if len(payload) >= aesgcm.NonceSize()+aesgcm.Overhead() {
			nonce := payload[:aesgcm.NonceSize()]
			ciphertext := payload[aesgcm.NonceSize():]
			plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
			if err == nil {
				return string(plaintext), nil
			}
		}
		// If AES fails, fall back to DPAPI
	}

	// Try DPAPI
	if runtime.GOOS == "windows" {
		decrypted, err := decrypt(encryptedValue)
		if err != nil {
			return "", err
		}
		return string(decrypted), nil
	}

	// สำหรับ OS อื่น assume plaintext หรืออะไร แต่จริงๆ ไม่
	return string(encryptedValue), nil
}

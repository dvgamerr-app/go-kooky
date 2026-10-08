//go:build windows

package browser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	_ "modernc.org/sqlite"
)

// This file exercises Opera's path resolution end-to-end on Windows, reusing
// the exact same Chromium code path as Chrome/Edge/Brave (GetBasePath,
// GetBrowserInfo, GetProfiles, getCookiePaths). It builds a synthetic
// Local State + "Network/Cookies" fixture under a temp %APPDATA%, protecting
// the fixture's AES key with real Windows DPAPI (CryptProtectData) so the
// production getAESKey()/decrypt() path is exercised unmodified, exactly as
// it would be against a real Opera profile. No real browser or cookie data
// is used.

var procEncryptData = syscall.NewLazyDLL("Crypt32.dll").NewProc("CryptProtectData")

func cryptProtectDataForTest(t *testing.T, data []byte) []byte {
	t.Helper()
	input := DataBlob{cbData: uint32(len(data)), pbData: &data[0]}
	var output DataBlob
	result, _, err := procEncryptData.Call(
		uintptr(unsafe.Pointer(&input)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&output)),
	)
	if result == 0 {
		t.Fatalf("CryptProtectData() failed: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	protected := make([]byte, output.cbData)
	copy(protected, unsafe.Slice(output.pbData, output.cbData))
	return protected
}

func writeFakeOperaProfile(t *testing.T, appData string) (rawKey []byte, profileName string) {
	t.Helper()

	rawKey = make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	protectedKey := cryptProtectDataForTest(t, rawKey)
	encodedKey := base64.StdEncoding.EncodeToString(append([]byte("DPAPI"), protectedKey...))

	profileName = "Default"
	localState := map[string]any{
		"os_crypt": map[string]any{"encrypted_key": encodedKey},
		"profile":  map[string]any{"info_cache": map[string]any{profileName: map[string]any{}}},
	}
	root := filepath.Join(appData, "Opera Software", "Opera Stable")
	if err := os.MkdirAll(filepath.Join(root, profileName, "Network"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	lsData, err := json.Marshal(localState)
	if err != nil {
		t.Fatalf("marshal Local State: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "Local State"), lsData, 0o644); err != nil {
		t.Fatalf("write Local State: %v", err)
	}

	block, err := aes.NewCipher(rawKey)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM() error = %v", err)
	}
	nonce := []byte("test-nonce12")
	// 32 bytes of Chromium metadata filler, followed by the real cookie value.
	plaintext := append(make([]byte, 32), []byte("placeholder-test-value")...)
	encrypted := append([]byte("v10"), nonce...)
	encrypted = gcm.Seal(encrypted, nonce, plaintext, nil)

	dbPath := filepath.Join(root, profileName, "Network", "Cookies")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open Cookies db: %v", err)
	}
	defer db.Close()

	const schema = `CREATE TABLE cookies (
		host_key TEXT, name TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER,
		is_secure INTEGER, is_httponly INTEGER, creation_utc INTEGER, last_access_utc INTEGER
	)`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO cookies (host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly, creation_utc, last_access_utc)
		 VALUES ('example.test', 'session', ?, '/', 0, 0, 0, 0, 0)`,
		encrypted,
	); err != nil {
		t.Fatalf("insert fixture row: %v", err)
	}

	return rawKey, profileName
}

func TestOperaProfileDiscoveryAndCookies(t *testing.T) {
	appData := t.TempDir()
	t.Setenv("APPDATA", appData)

	_, wantProfile := writeFakeOperaProfile(t, appData)

	profiles, err := GetProfiles("opera")
	if err != nil {
		t.Fatalf("GetProfiles() error = %v", err)
	}
	if len(profiles) != 1 || profiles[0] != wantProfile {
		t.Fatalf("GetProfiles() = %v, want [%q]", profiles, wantProfile)
	}

	cs := NewCookieStore("opera", wantProfile)
	cookies, err := cs.GetCookies()
	if err != nil {
		t.Fatalf("GetCookies() error = %v", err)
	}
	if len(cookies) != 1 {
		t.Fatalf("GetCookies() returned %d cookies, want 1", len(cookies))
	}
	if cookies[0].Host != "example.test" || cookies[0].Name != "session" || cookies[0].Value != "placeholder-test-value" {
		t.Fatalf("GetCookies()[0] = %+v, unexpected fields", cookies[0])
	}
}

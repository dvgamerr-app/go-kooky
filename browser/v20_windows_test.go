//go:build windows

package browser

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestChromiumV20StoreReportsAppBoundEncryption adds a v20-prefixed row (the
// shape Chrome/Edge/Brave now write) to the synthetic Opera fixture and checks
// that CookiesForHost reports ErrAppBoundEncryption instead of returning the
// DecryptFailedPlaceholder as if it were a real cookie value.
func TestChromiumV20StoreReportsAppBoundEncryption(t *testing.T) {
	appData := t.TempDir()
	t.Setenv("APPDATA", appData)
	_, profile := writeFakeOperaProfile(t, appData)

	dbPath := filepath.Join(appData, "Opera Software", "Opera Stable", profile, "Network", "Cookies")
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("fixture cookies db missing: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open cookies db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(
		`INSERT INTO cookies (host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly, creation_utc, last_access_utc)
		 VALUES ('.v20.test', 'ltoken_v2', ?, '/', 0, 0, 0, 0, 0)`,
		[]byte("v20placeholder-ciphertext"),
	); err != nil {
		t.Fatalf("insert v20 row: %v", err)
	}

	cs := NewCookieStore("opera", profile)

	// The legacy v10 row from the same store still works.
	if got, err := cs.CookiesForHost("example.test"); err != nil || len(got) != 1 {
		t.Fatalf("CookiesForHost(v10 host) = %v, %v; want 1 cookie", got, err)
	}

	got, err := cs.CookiesForHost("api.v20.test")
	if !errors.Is(err, ErrAppBoundEncryption) {
		t.Fatalf("CookiesForHost(v20 host) error = %v, want ErrAppBoundEncryption", err)
	}
	if len(got) != 0 {
		t.Fatalf("CookiesForHost(v20 host) returned %d cookies, want none", len(got))
	}
}

package browser

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	_ "modernc.org/sqlite"
)

// writeFakeFirefoxProfile builds a minimal profiles.ini + cookies.sqlite tree
// under root, mimicking a real Firefox profile directory without any real
// cookie data, and returns the profile name recorded in profiles.ini.
func writeFakeFirefoxProfile(t *testing.T, root string) string {
	t.Helper()

	profileDir := filepath.Join(root, "Profiles", "abc123.default-release")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	ini := "[Profile0]\n" +
		"Name=default-release\n" +
		"IsRelative=1\n" +
		"Path=Profiles/abc123.default-release\n" +
		"Default=1\n"
	if err := os.WriteFile(filepath.Join(root, "profiles.ini"), []byte(ini), 0o644); err != nil {
		t.Fatalf("write profiles.ini: %v", err)
	}

	dbPath := filepath.Join(profileDir, "cookies.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open cookies.sqlite: %v", err)
	}
	defer db.Close()

	const schema = `CREATE TABLE moz_cookies (
		host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER,
		isSecure INTEGER, isHttpOnly INTEGER, creationTime INTEGER, lastAccessed INTEGER
	)`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO moz_cookies (host, name, value, path, expiry, isSecure, isHttpOnly, creationTime, lastAccessed)
		 VALUES ('example.test', 'session', 'placeholder-test-value', '/', 0, 0, 0, 0, 0)`,
	); err != nil {
		t.Fatalf("insert fixture row: %v", err)
	}

	return "default-release"
}

// setFirefoxRootEnv points firefoxRoot() at a temp directory for the current
// OS and returns the resulting root, so the test exercises the exact path
// firefoxRoot() computes rather than reimplementing it.
func setFirefoxRootEnv(t *testing.T, tmp string) string {
	t.Helper()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("APPDATA", tmp)
	default:
		t.Setenv("HOME", tmp)
	}
	return firefoxRoot()
}

func TestFirefoxProfileDiscoveryAndCookies(t *testing.T) {
	tmp := t.TempDir()
	root := setFirefoxRootEnv(t, tmp)
	wantProfile := writeFakeFirefoxProfile(t, root)

	profiles, err := GetProfiles("firefox")
	if err != nil {
		t.Fatalf("GetProfiles() error = %v", err)
	}
	if len(profiles) != 1 || profiles[0] != wantProfile {
		t.Fatalf("GetProfiles() = %v, want [%q]", profiles, wantProfile)
	}

	cs := NewCookieStore("firefox", wantProfile)
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

func TestFirefoxUnknownProfileReturnsError(t *testing.T) {
	tmp := t.TempDir()
	setFirefoxRootEnv(t, tmp)
	writeFakeFirefoxProfile(t, firefoxRoot())

	cs := NewCookieStore("firefox", "does-not-exist")
	if _, err := cs.GetCookies(); err == nil {
		t.Fatal("GetCookies() error = nil, want error for unknown profile")
	}
}

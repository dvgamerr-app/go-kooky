package browser

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestDecryptValueRejectsAppBoundV20(t *testing.T) {
	_, err := decryptValue([]byte("v20-not-real-ciphertext"), make([]byte, 32))
	if !errors.Is(err, ErrAppBoundEncryption) {
		t.Fatalf("decryptValue(v20) error = %v, want ErrAppBoundEncryption", err)
	}
}

func TestChromeEdgeBraveAreRejected(t *testing.T) {
	for _, name := range []string{"chrome", "edge", "brave"} {
		if path, _ := GetBrowserInfo(name); path != "" {
			t.Errorf("GetBrowserInfo(%q) = %q, want unsupported", name, path)
		}
		if _, err := GetProfiles(name); !errors.Is(err, ErrAppBoundEncryption) {
			t.Errorf("GetProfiles(%q) error = %v, want ErrAppBoundEncryption", name, err)
		}
	}
}

func TestCookieMatchesHost(t *testing.T) {
	tests := []struct {
		cookieHost, host string
		want             bool
	}{
		{".example.test", "api.example.test", true},
		{".example.test", "example.test", true},
		{"example.test", "api.example.test", true},
		{"api.example.test", "example.test", false},
		{".example.test", "badexample.test", false},
		{"", "example.test", false},
	}
	for _, tt := range tests {
		if got := (Cookie{Host: tt.cookieHost}).MatchesHost(tt.host); got != tt.want {
			t.Errorf("Cookie{Host:%q}.MatchesHost(%q) = %v, want %v", tt.cookieHost, tt.host, got, tt.want)
		}
	}
}

func TestExpiryConversion(t *testing.T) {
	if !chromiumExpires(0).IsZero() || !firefoxExpires(0).IsZero() {
		t.Fatal("zero expiry must map to a zero (session) time")
	}
	// 2030-01-01T00:00:00Z in each unit.
	want := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := firefoxExpires(want.Unix()); !got.Equal(want) {
		t.Errorf("firefoxExpires(seconds) = %v, want %v", got, want)
	}
	if got := firefoxExpires(want.UnixMilli()); !got.Equal(want) {
		t.Errorf("firefoxExpires(milliseconds) = %v, want %v", got, want)
	}
	us := (want.Unix() + 11644473600) * 1_000_000
	if got := chromiumExpires(us); !got.Equal(want) {
		t.Errorf("chromiumExpires() = %v, want %v", got, want)
	}
}

func TestFirefoxForkRoots(t *testing.T) {
	tmp := t.TempDir()
	base := setFirefoxRootEnv(t, tmp)
	for _, name := range []string{"firefox", "librewolf", "waterfox", "zen", "floorp"} {
		if path, btype := GetBrowserInfo(name); path == "" || btype != Firefox {
			t.Errorf("GetBrowserInfo(%q) = (%q, %v), want a Firefox-type browser", name, path, btype)
		}
	}
	for _, name := range []string{"librewolf", "waterfox", "zen", "floorp"} {
		if got := firefoxRootFor(name); got == base {
			t.Errorf("firefoxRootFor(%q) = %q, must differ from the firefox root", name, got)
		}
	}
}

func TestFirefoxCookiesForHostIncludesWALRows(t *testing.T) {
	tmp := t.TempDir()
	root := setFirefoxRootEnv(t, tmp)
	profile := writeFakeFirefoxProfile(t, root)

	dbPath := filepath.Join(root, "Profiles", "abc123.default-release", "cookies.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open cookies.sqlite: %v", err)
	}
	defer db.Close()
	// Keep one connection so the new row stays in the -wal sidecar, as it does
	// while a real Firefox is running.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatalf("enable WAL: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO moz_cookies (host, name, value, path, expiry, isSecure, isHttpOnly, creationTime, lastAccessed)
		 VALUES ('.wal.test', 'ltoken_v2', 'placeholder-wal-value', '/', 4102444800000, 1, 1, 0, 0)`,
	); err != nil {
		t.Fatalf("insert WAL row: %v", err)
	}

	cs := NewCookieStore("firefox", profile)
	got, err := cs.CookiesForHost("api.wal.test")
	if err != nil {
		t.Fatalf("CookiesForHost() error = %v", err)
	}
	if len(got) != 1 || got[0].Name != "ltoken_v2" || got[0].Value != "placeholder-wal-value" {
		t.Fatalf("CookiesForHost() = %+v, want the WAL-resident ltoken_v2 cookie", got)
	}
	if !got[0].Secure || !got[0].HttpOnly || got[0].Expires.Year() != 2100 {
		t.Fatalf("CookiesForHost() attributes = %+v, want secure/httponly/year 2100", got[0])
	}

	if other, err := cs.CookiesForHost("unrelated.test"); err != nil || len(other) != 0 {
		t.Fatalf("CookiesForHost(unrelated) = %v, %v; want no cookies and no error", other, err)
	}
}

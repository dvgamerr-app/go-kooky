package browser

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/dvgamerr-app/go-kooky/v2/browser/firefox"
	jsoniter "github.com/json-iterator/go"
	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite"
)

type BrowserType int

const (
	Chromium BrowserType = iota
	Firefox
)

var stdJson = jsoniter.ConfigCompatibleWithStandardLibrary

type CookieStore struct {
	Browser string
	Profile string
	Path    string
}

func NewCookieStore(browser, profile string) *CookieStore {
	return &CookieStore{
		Browser: browser,
		Profile: profile,
	}
}

func GetBrowserInfo(browser string) (browserPath string, btype BrowserType) {
	switch browser {
	// Chrome, Edge and Brave are intentionally absent: their cookies use
	// App-Bound Encryption (v20) and cannot be read (see ErrAppBoundEncryption).
	case "opera":
		return "Opera Software/Opera Stable", Chromium
	case "firefox":
		return "Mozilla/Firefox", Firefox
	case "librewolf", "waterfox", "zen", "floorp":
		// Firefox forks share Firefox's profiles.ini + cookies.sqlite layout;
		// only the profile root differs (see firefoxRootFor).
		return browser, Firefox
	default:
		return "", Chromium // default to chromium
	}
}

func GetBasePath(btype BrowserType, browser string) string {
	homeDir, _ := os.UserHomeDir()
	var base string
	switch runtime.GOOS {
	case "windows":
		if browser == "opera" || btype == Firefox {
			base = os.Getenv("APPDATA")
		} else {
			base = os.Getenv("LOCALAPPDATA")
		}
	case "darwin":
		base = filepath.Join(homeDir, "Library", "Application Support")
	case "linux":
		if btype == Firefox {
			base = filepath.Join(homeDir, ".mozilla", "firefox")
		} else {
			base = filepath.Join(homeDir, ".config")
		}
	default:
		base = homeDir
	}
	return base
}

// firefoxRoot returns the directory containing profiles.ini, using Firefox's
// actual per-OS convention. This intentionally does not reuse GetBasePath:
// on Linux, GetBasePath already returns the full "<home>/.mozilla/firefox"
// root for Firefox, and on macOS the real subpath is "Firefox", not
// "Mozilla/Firefox" as GetBrowserInfo reports for Windows — joining either
// of those onto a shared browserPath double-nests or mis-nests the path.
func firefoxRoot() string { return firefoxRootFor("firefox") }

// firefoxRootFor is firefoxRoot for any Firefox-family browser identifier.
// Fork locations other than Firefox itself follow each project's documented
// default and have not been verified against a real install.
func firefoxRootFor(browser string) string {
	homeDir, _ := os.UserHomeDir()
	var win, mac, nix string // path below %APPDATA%, Application Support, and $HOME
	switch browser {
	case "librewolf":
		win, mac, nix = "librewolf", "LibreWolf", ".librewolf"
	case "waterfox":
		win, mac, nix = "Waterfox", "Waterfox", ".waterfox"
	case "zen":
		win, mac, nix = "zen", "zen", ".zen"
	case "floorp":
		win, mac, nix = "Floorp", "Floorp", ".floorp"
	default:
		win, mac, nix = filepath.Join("Mozilla", "Firefox"), "Firefox", filepath.Join(".mozilla", "firefox")
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), win)
	case "darwin":
		return filepath.Join(homeDir, "Library", "Application Support", mac)
	default: // linux and other unix-likes
		return filepath.Join(homeDir, nix)
	}
}

// findFirefoxCookieStore locates the cookies.sqlite path for a named Firefox
// profile by reading profiles.ini, matching Chromium's profile-name lookup.
func findFirefoxCookieStore(browser, profile string) (string, error) {
	stores, err := firefox.FindCookieStoreFiles(firefoxRootFor(browser), browser, "cookies.sqlite")
	if err != nil {
		return "", err
	}
	for _, s := range stores {
		if s.Profile == profile {
			return s.Path, nil
		}
	}
	return "", fmt.Errorf("firefox profile not found: %s", profile)
}

func getCookiePaths(browser, profile string) (cookiePath, localStatePath string, btype BrowserType) {
	browserPath, btype := GetBrowserInfo(browser)

	base := GetBasePath(btype, browser)

	switch btype {
	case Chromium:
		cookiePath = filepath.Join(base, browserPath, profile, "Network", "Cookies")
		localStatePath = filepath.Join(base, browserPath, "Local State")
	case Firefox:
		cookiePath, _ = findFirefoxCookieStore(browser, profile)
		localStatePath = ""
	}

	return cookiePath, localStatePath, btype
}

func (cs *CookieStore) GetCookies() ([]Cookie, error) {
	cookiePath, localStatePath, btype := getCookiePaths(cs.Browser, cs.Profile)

	if cookiePath == "" {
		return nil, fmt.Errorf("could not resolve cookie store path for %s profile %q", cs.Browser, cs.Profile)
	}
	if _, err := os.Stat(cookiePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("cookies file not found: %s", cookiePath)
	}

	tempDB, cleanup, err := copyStore(cookiePath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	db, err := sql.Open("sqlite", tempDB)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var cookies []Cookie

	if btype == Chromium {
		key, err := getAESKey(localStatePath)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to read AES key")
			key = nil
		}

		rows, err := db.Query("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly, creation_utc, last_access_utc FROM cookies")
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var cookie Cookie
			var encryptedValue []byte

			err := rows.Scan(
				&cookie.Host,
				&cookie.Name,
				&encryptedValue,
				&cookie.Path,
				&cookie.ExpiresUTC,
				&cookie.IsSecure,
				&cookie.IsHttpOnly,
				&cookie.CreationUTC,
				&cookie.LastAccessUTC,
			)
			if err != nil {
				continue
			}

			cookie.Expires = chromiumExpires(cookie.ExpiresUTC)

			decryptedValue, err := decryptValue(encryptedValue, key)
			if err != nil {
				decryptedValue = DecryptFailedPlaceholder
				cookie.decryptErr = err
			} else {
				// Chromium's v10/v11 AES-GCM decryption prepends a 32-byte
				// metadata header to the plaintext cookie value for every
				// Chromium-based browser (Chrome, Edge, Opera, Brave), not
				// just Opera — strip it to get the real cookie value.
				if len(decryptedValue) > 32 {
					decryptedValue = decryptedValue[32:]
				}
			}
			cookie.Value = decryptedValue
			cookies = append(cookies, cookie)
		}
	} else if btype == Firefox {
		// Firefox cookies are not encrypted
		rows, err := db.Query("SELECT host, name, value, path, expiry, isSecure, isHttpOnly, creationTime, lastAccessed FROM moz_cookies")
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var cookie Cookie
			err := rows.Scan(
				&cookie.Host,
				&cookie.Name,
				&cookie.Value,
				&cookie.Path,
				&cookie.ExpiresUTC,
				&cookie.IsSecure,
				&cookie.IsHttpOnly,
				&cookie.CreationUTC,
				&cookie.LastAccessUTC,
			)
			if err != nil {
				continue
			}
			cookie.Expires = firefoxExpires(cookie.ExpiresUTC)
			cookies = append(cookies, cookie)
		}
	}

	return cookies, nil
}

// copyStore copies a cookie database (and its -wal sidecar, which holds
// cookies Firefox has not yet checkpointed) into a private temp directory so
// the live browser's lock is never contended. The returned cleanup removes it.
func copyStore(src string) (dbPath string, cleanup func(), err error) {
	dir, err := os.MkdirTemp(TEMP_DIR, "store-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	dbPath = filepath.Join(dir, "cookies.db")
	if err := copyFile(src, dbPath); err != nil {
		cleanup()
		return "", nil, err
	}
	if _, statErr := os.Stat(src + "-wal"); statErr == nil {
		// Best effort: a missing or unreadable WAL only means fewer recent rows.
		_ = copyFile(src+"-wal", dbPath+"-wal")
	}
	return dbPath, cleanup, nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// CookiesForHost returns the decrypted cookies that apply to host as
// net/http cookies. When matching cookies exist but none could be decrypted
// the underlying cause is returned (errors.Is(err, ErrAppBoundEncryption)
// identifies unsupported Chromium v20 stores).
func (cs *CookieStore) CookiesForHost(host string) ([]*http.Cookie, error) {
	all, err := cs.GetCookies()
	if err != nil {
		return nil, err
	}
	var out []*http.Cookie
	var failed int
	var cause error
	for _, c := range all {
		if !c.MatchesHost(host) {
			continue
		}
		if !c.Decrypted() {
			failed++
			if cause == nil {
				cause = c.decryptErr
			}
			continue
		}
		out = append(out, c.HTTPCookie())
	}
	if len(out) == 0 && failed > 0 {
		if cause == nil {
			cause = fmt.Errorf("decryption failed")
		}
		return nil, fmt.Errorf("%s/%s: %d cookies for %s could not be decrypted: %w", cs.Browser, cs.Profile, failed, host, cause)
	}
	return out, nil
}
func GetProfiles(browser string) ([]string, error) {
	browserPath, btype := GetBrowserInfo(browser)
	if browserPath == "" {
		switch browser {
		case "chrome", "edge", "brave":
			return nil, fmt.Errorf("unsupported browser %s: %w", browser, ErrAppBoundEncryption)
		}
		return nil, fmt.Errorf("unsupported browser: %s", browser)
	}
	base := GetBasePath(btype, browser)

	switch btype {
	case Chromium:
		localStatePath := filepath.Join(base, browserPath, "Local State")
		data, err := os.ReadFile(localStatePath)
		if err != nil {
			return nil, err
		}

		var localState map[string]any
		if err := stdJson.Unmarshal(data, &localState); err != nil {
			return nil, err
		}

		profile, ok := localState["profile"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("profile section not found")
		}

		infoCache, ok := profile["info_cache"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("info_cache section not found")
		}

		var profiles []string
		for key := range infoCache {
			profiles = append(profiles, key)
		}

		return profiles, nil
	case Firefox:
		stores, err := firefox.FindCookieStoreFiles(firefoxRootFor(browser), browser, "cookies.sqlite")
		if err != nil {
			return nil, err
		}
		var profiles []string
		for _, s := range stores {
			profiles = append(profiles, s.Profile)
		}
		return profiles, nil
	}

	return nil, fmt.Errorf("unsupported browser type")
}

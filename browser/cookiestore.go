package browser

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite"
)

type BrowserType int

const (
	Chromium BrowserType = iota
	Firefox
)

type CookieStore struct {
	Browser string
	Profile string
}

func NewCookieStore(browser, profile string) *CookieStore {
	return &CookieStore{
		Browser: browser,
		Profile: profile,
	}
}

func getBrowserInfo(browser string) (browserPath string, btype BrowserType) {
	switch browser {
	case "chrome":
		return "Google/Chrome", Chromium
	case "edge":
		return "Microsoft/Edge", Chromium
	case "opera":
		return "Opera Software/Opera Stable", Chromium
	case "brave":
		return "BraveSoftware/Brave-Browser", Chromium
	case "firefox":
		return "Mozilla/Firefox/Profiles", Firefox
	default:
		return "", Chromium // default to chromium
	}
}

func getCookiePaths(browser, profile string) (cookiePath, localStatePath string, btype BrowserType) {
	browserPath, btype := getBrowserInfo(browser)

	homeDir, _ := os.UserHomeDir()
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("APPDATA")
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

	switch btype {
	case Chromium:
		cookiePath = filepath.Join(base, browserPath, profile, "Network", "Cookies")
		localStatePath = filepath.Join(base, browserPath, "Local State")
	case Firefox:
		cookiePath = filepath.Join(base, browserPath, profile, "cookies.sqlite")
		localStatePath = ""
	}

	return cookiePath, localStatePath, btype
}

func (cs *CookieStore) GetCookies() ([]Cookie, error) {
	cookiePath, localStatePath, btype := getCookiePaths(cs.Browser, cs.Profile)

	if _, err := os.Stat(cookiePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("cookies file not found: %s", cookiePath)
	}

	// Copy to temp
	input, err := os.ReadFile(cookiePath)
	if err != nil {
		return nil, err
	}
	tempDB := filepath.Join(TEMP_DIR, cs.Browser+"_"+cs.Profile)
	err = os.WriteFile(tempDB, input, 0644)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempDB)

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

			decryptedValue, err := decryptValue(encryptedValue, key)
			if err != nil {
				decryptedValue = "[DECRYPT FAILED]"
			} else {
				// For Opera, trim header
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
			cookies = append(cookies, cookie)
		}
	}

	return cookies, nil
}
func GetProfiles(browser string) ([]string, error) {
	browserPath, btype := getBrowserInfo(browser)
	if browserPath == "" {
		return nil, fmt.Errorf("unsupported browser: %s", browser)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("APPDATA")
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
	profilesDir := filepath.Join(base, browserPath)
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return nil, err
	}
	var profiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			profiles = append(profiles, entry.Name())
		}
	}
	return profiles, nil
}

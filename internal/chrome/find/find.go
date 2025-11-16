package find

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

type chromeCookieStoreFile struct {
	Path             string
	Browser          string
	Profile          string
	ProfileDir       string // folder name (e.g., "Default", "Profile 1")
	OS               string
	IsDefaultProfile bool
}

// appendCookieStoreFile checks if the given path exists and appends a chromeCookieStoreFile to files if so.
func appendCookieStoreFile(files *[]*chromeCookieStoreFile, path, browser, profile, profileDir string, isDefault bool) {
	if _, err := os.Stat(path); err == nil {
		*files = append(*files, &chromeCookieStoreFile{
			Browser:          browser,
			Profile:          profile,
			ProfileDir:       profileDir,
			IsDefaultProfile: isDefault,
			Path:             path,
			OS:               runtime.GOOS,
		})
	}
}

// chromeRoots and chromiumRoots could be put into the github.com/kooky/browser/{chrome,chromium} packages.
// It might be better though to keep those 2 together here as they are based on the same source.
func FindChromeCookieStoreFiles() ([]*chromeCookieStoreFile, error) {
	return FindCookieStoreFiles(chromeRoots, `chrome`)
}
func FindChromiumCookieStoreFiles() ([]*chromeCookieStoreFile, error) {
	return FindCookieStoreFiles(chromiumRoots, `chromium`)
}

func FindCookieStoreFiles(rootsFunc func() ([]string, error), browserName string) ([]*chromeCookieStoreFile, error) {
	if rootsFunc == nil {
		return nil, errors.New(`passed roots function is nil`)
	}

	var files []*chromeCookieStoreFile

	roots, err := rootsFunc()
	if err != nil {
		return nil, err
	}
	for _, root := range roots {
		localStateBytes, err := os.ReadFile(filepath.Join(root, `Local State`))
		if err != nil {
			continue
		}
		var localState struct {
			Profile struct {
				InfoCache map[string]struct {
					IsUsingDefaultName bool `json:"is_using_default_name"`
					Name               string
				} `json:"info_cache"`
			}
		}
		if err := json.Unmarshal(localStateBytes, &localState); err != nil {
			// fallback - json file exists, json structure unknown
			cookiePathNetwork := filepath.Join(root, "Default", "Network", "Cookies")
			cookiePath := filepath.Join(root, "Default", "Cookies")
			appendCookieStoreFile(&files, cookiePathNetwork, browserName, "Profile 1", "Default", true)
			appendCookieStoreFile(&files, cookiePath, browserName, "Profile 1", "Default", true)
			continue

		}

		for profDir, profStr := range localState.Profile.InfoCache {
			profileName := profStr.Name
			if profileName == "" {
				profileName = profDir
			}
			cookiePathNetwork := filepath.Join(root, profDir, `Network`, `Cookies`)
			cookiePath := filepath.Join(root, profDir, `Cookies`)
			appendCookieStoreFile(&files, cookiePathNetwork, browserName, profileName, profDir, profStr.IsUsingDefaultName)
			appendCookieStoreFile(&files, cookiePath, browserName, profileName, profDir, profStr.IsUsingDefaultName)
		}
	}
	return files, nil
}

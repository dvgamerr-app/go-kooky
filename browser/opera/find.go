package opera

import (
	"os"
	"path/filepath"

	"github.com/dvgamerr-app/go-kooky"
	"github.com/dvgamerr-app/go-kooky/internal/chrome"
	"github.com/dvgamerr-app/go-kooky/internal/chrome/find"
	"github.com/dvgamerr-app/go-kooky/internal/cookies"
)

type operaFinder struct{}

var _ kooky.CookieStoreFinder = (*operaFinder)(nil)

func init() {
	kooky.RegisterFinder(`opera`, &operaFinder{})
}

func (f *operaFinder) FindCookieStores() ([]kooky.CookieStore, error) {
	var ret []kooky.CookieStore

	// Opera Presto (old version)
	roots, err := operaPrestoRoots()
	if err != nil {
		return nil, err
	}
	for _, root := range roots {
		cookiePath := filepath.Join(root, `cookies4.dat`)
		if _, err := os.Stat(cookiePath); err == nil {
			ret = append(
				ret,
				&cookies.CookieJar{
					CookieStore: &operaCookieStore{
						CookieStore: &operaPrestoCookieStore{
							DefaultCookieStore: cookies.DefaultCookieStore{
								BrowserStr:           `opera`,
								IsDefaultProfileBool: true,
								FileNameStr:          cookiePath,
							},
						},
					},
				},
			)
		}
	}

	// Opera Blink (Chromium-based) - use Chrome's find logic for profiles
	files, err := find.FindCookieStoreFiles(operaBlinkRoots, `opera`)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		ret = append(
			ret,
			&cookies.CookieJar{
				CookieStore: &operaCookieStore{
					CookieStore: &chrome.CookieStore{
						DefaultCookieStore: cookies.DefaultCookieStore{
							BrowserStr:           file.Browser,
							ProfileStr:           file.Profile,
							ProfileDirStr:        file.ProfileDir,
							OSStr:                file.OS,
							IsDefaultProfileBool: file.IsDefaultProfile,
							FileNameStr:          file.Path,
						},
					},
				},
			},
		)
	}

	return ret, nil
}

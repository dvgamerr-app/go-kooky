package firefox

import (
	"path/filepath"
	"strings"

	"github.com/go-ini/ini"
)

type CookieStoreFile struct {
	Path             string
	Browser          string
	Profile          string
	IsDefaultProfile bool
}

func FindCookieStoreFiles(root string, browserName, fileName string) ([]*CookieStoreFile, error) {
	iniFile := filepath.Join(root, `profiles.ini`)
	profIni, err := ini.Load(iniFile)
	if err != nil {
		return nil, err
	}
	var defaultProfileFolder string
	profiles := make(map[string]*ini.Section)
	for _, sec := range profIni.SectionStrings() {
		cfgSec := profIni.Section(sec)
		if cfgSec.Key(`Locked`).String() == `1` {
			defaultProfileFolder = cfgSec.Key(`Default`).String()
		}
		if strings.HasPrefix(sec, `Profile`) {
			profiles[sec] = cfgSec
		}
	}
	var results []*CookieStoreFile
	for _, cfgSec := range profiles {
		profileFolder := cfgSec.Key(`Path`).String()
		var defaultBrowser bool
		if profileFolder == defaultProfileFolder /* || cfgSec.Key(`Default`).String() == `1` */ {
			defaultBrowser = true
		}
		profileFolder = filepath.FromSlash(profileFolder)
		if cfgSec.Key(`IsRelative`).String() == `1` {
			// relative profile path
			profileFolder = filepath.Join(root, profileFolder)
		}
		st := &CookieStoreFile{
			Browser:          browserName,
			Profile:          cfgSec.Key(`Name`).String(),
			IsDefaultProfile: defaultBrowser,
			Path:             filepath.Join(profileFolder, fileName),
		}
		results = append(results, st)
	}
	return results, nil
}

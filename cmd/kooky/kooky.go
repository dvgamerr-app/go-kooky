package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/dvgamerr-app/go-kooky"
	_ "github.com/dvgamerr-app/go-kooky/browser/all"
	"github.com/spf13/cobra"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	profile        string
	defaultProfile bool
	showExpired    bool
	domain         string
	name           string
	export         string
	debug          bool
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	var rootCmd = &cobra.Command{
		Use:   "kooky [browsers...]",
		Short: "Extract cookies from browser cookie stores",
		Long:  `Kooky is a CLI tool to extract and export cookies from various browser cookie stores.`,
		Run:   runKooky,
		Example: `  kooky                    # Extract from all browsers
  kooky opera              # Extract from Opera only
  kooky opera edge chrome  # Extract from multiple browsers`,
	}

	rootCmd.Flags().StringVarP(&profile, "profile", "p", "", "profile filter")
	rootCmd.Flags().BoolVarP(&defaultProfile, "default-profile", "q", false, "only default profile(s)")
	rootCmd.Flags().BoolVarP(&showExpired, "expired", "e", false, "show expired cookies")
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "cookie domain filter (partial)")
	rootCmd.Flags().StringVarP(&name, "name", "n", "", "cookie name filter (exact)")
	rootCmd.Flags().StringVarP(&export, "export", "o", "", "export cookies in netscape format")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "enable debug logging")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Failed to execute command")
	}
}

func runKooky(cmd *cobra.Command, args []string) {
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// Use args as browser filters
	cookieStores := kooky.FindAllCookieStores(args...)

	var cookiesExport []*kooky.Cookie

	var f io.Writer
	var w *tabwriter.Writer
	if len(export) > 0 {
		if export == `-` {
			f = os.Stdout
		} else {
			fl, err := os.OpenFile(export, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				log.Fatal().Err(err).Str("file", export).Msg("Failed to open export file")
			}
			defer fl.Close()
			f = fl
		}
	} else {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	}
	trimLen := 45
	for _, store := range cookieStores {
		defer store.Close()

		log.Debug().
			Str("browser", store.Browser()).
			Str("profile", store.Profile()).
			Msg("Read")
		if len(profile) > 0 {
			// Check both profile name and profile directory
			profileMatches := store.Profile() == profile
			// Try to get ProfileDir if available
			if !profileMatches {
				if cs, ok := store.(interface{ ProfileDir() string }); ok {
					profileMatches = cs.ProfileDir() == profile
				}
			}
			if !profileMatches {
				continue
			}
		}

		if defaultProfile && !store.IsDefaultProfile() {
			continue
		}

		// cookie filters
		var filters []kooky.Filter
		if !showExpired {
			filters = append(filters, kooky.Valid)
		}
		if len(domain) > 0 {
			filters = append(filters, kooky.DomainContains(domain))
		}
		if len(name) > 0 {
			filters = append(filters, kooky.Name(name))
		}

		cookies, err := store.ReadCookies(filters...)
		if err != nil {
			continue
		}

		if len(export) > 0 {
			cookiesExport = append(cookiesExport, cookies...)
		} else {
			for _, cookie := range cookies {
				container := cookie.Container
				if len(container) > 0 {
					container = ` [` + container + `]`
				}
				fmt.Fprintf(
					w,
					"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					store.Browser(),
					store.Profile(),
					container,
					trimStr(store.FilePath(), trimLen),
					trimStr(cookie.Domain, trimLen),
					trimStr(cookie.Name, trimLen),
					// be careful about raw bytes
					trimStr(strings.Trim(fmt.Sprintf(`%q`, cookie.Value), `"`), trimLen),
					cookie.Expires.Format(`2006.01.02 15:04:05`),
				)
			}
		}
	}
	if len(export) > 0 {
		kooky.ExportCookies(f, cookiesExport)
	} else {
		w.Flush()
	}
}

func trimStr(str string, length int) string {
	if len(str) <= length {
		return str
	}
	if length > 0 {
		return str[:length-1] + "\u2026" // "..."
	}
	return str[:length]
}

// TODO: "kooky -b firefox -o /dev/stdout | head" hangs

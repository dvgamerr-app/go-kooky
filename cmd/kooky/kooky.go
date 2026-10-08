package main

import (
	"os"

	"github.com/dvgamerr-app/go-kooky/v2/browser"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// supportedBrowsers mirrors the identifiers documented in README.md.
var supportedBrowsers = []string{"firefox", "librewolf", "waterfox", "zen", "floorp", "opera"}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	rootCmd := &cobra.Command{
		Use:   "kooky [browsers...]",
		Short: "Extract cookies from browser cookie stores",
		Long:  `Kooky is a CLI tool to extract and export cookies from various browser cookie stores.`,
		Run:   runKooky,
		Example: `  kooky                    # Extract from all browsers
	  kooky opera              # Extract from Opera only
	  kooky firefox opera      # Extract from multiple browsers`,
	}

	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Failed to execute command")
	}
}

// runKooky reports a per-profile cookie summary for each requested browser
// (or every supported browser when none is named). It never logs a cookie
// name, domain, or decrypted value — only counts — so command output is
// always safe to paste or share.
func runKooky(_ *cobra.Command, args []string) {
	browsers := args
	if len(browsers) == 0 {
		browsers = supportedBrowsers
	}

	exitCode := 0
	for _, name := range browsers {
		if err := summarizeBrowser(name); err != nil {
			log.Error().Err(err).Str("browser", name).Msg("Failed to read browser profiles")
			exitCode = 1
		}
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func summarizeBrowser(name string) error {
	profiles, err := browser.GetProfiles(name)
	if err != nil {
		return err
	}
	if len(profiles) == 0 {
		log.Warn().Str("browser", name).Msg("No profiles found")
		return nil
	}

	for _, profile := range profiles {
		cs := browser.NewCookieStore(name, profile)
		cookies, err := cs.GetCookies()
		if err != nil {
			log.Error().Err(err).Str("browser", name).Str("profile", profile).Msg("Failed to read cookies")
			continue
		}

		decrypted, failed := 0, 0
		for _, c := range cookies {
			if c.Value == browser.DecryptFailedPlaceholder {
				failed++
			} else {
				decrypted++
			}
		}

		log.Info().
			Str("browser", name).
			Str("profile", profile).
			Int("total", len(cookies)).
			Int("decrypted", decrypted).
			Int("failed", failed).
			Msg("Cookie summary")
	}

	return nil
}

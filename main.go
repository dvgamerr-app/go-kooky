package main

import (
	"os"

	"github.com/dvgamerr-app/go-kooky/v2/browser"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func processBrowser(browserName string) error {
	profiles, err := browser.GetProfiles(browserName)
	if err != nil {
		return err
	}

	log.Info().Strs("profiles", profiles).Msg("Available profiles")
	for _, v := range profiles {

		cs := browser.NewCookieStore(browserName, v)

		cookies, err := cs.GetCookies()
		if err != nil {
			return err
		}

		log.Info().Str("profile", v).Str("Browser", browserName).Int("Cookie Total", len(cookies)).Msg("Profile")
		for _, cookie := range cookies[:1] {
			value := cookie.Value
			if len(cookie.Value) > 32 {
				value = cookie.Value[:32] + "..."
			}
			log.Info().Str("Browser", browserName).Str("name", cookie.Name).Str("domain", cookie.Host).Str("value", value).Msg("Cookie")
		}
	}
	return nil
}

func main() {
	// err := processBrowser("opera")
	// if err != nil {
	// 	log.Fatal().Err(err).Msg("Failed to process browser")
	// }

	err := processBrowser("opera")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to process browser")
	}
}

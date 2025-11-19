package main

import (
	"os"

	"kooky/browser"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func main() {
	profiles, err := browser.GetProfiles("opera")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get profiles")
	}

	log.Info().Strs("profiles", profiles).Msg("Available profiles")
	cs := browser.NewCookieStore("opera", "Default")

	cookies, err := cs.GetCookies()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get cookies")
	}

	for _, cookie := range cookies {
		log.Info().Str("host", cookie.Host).Str("name", cookie.Name).Str("value", cookie.Value).Msg("Cookie")
	}
}

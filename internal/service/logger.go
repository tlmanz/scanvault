package service

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/tlmanz/scanvault/internal/config"
)

func buildLogger(cfg *config.Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}

	var base zerolog.Logger
	if cfg.LogFormat == "console" {
		base = zerolog.New(
			zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
		)
	} else {
		base = zerolog.New(os.Stderr)
	}

	return base.Level(level).With().Timestamp().Logger()
}
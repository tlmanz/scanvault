package infra

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

// NewLogger builds a zerolog.Logger from config settings.
func NewLogger(cfg *Config) zerolog.Logger {
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

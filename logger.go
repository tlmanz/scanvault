package scanvault

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

// buildLogger constructs a zerolog.Logger from Config.
// If Config.Logger is set, it is used as-is.
// Otherwise, a logger is built from LogLevel and LogFormat.
func buildLogger(cfg Config) zerolog.Logger {
	if cfg.Logger != nil {
		return *cfg.Logger
	}

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
		// json - structured output, suitable for production log aggregators.
		base = zerolog.New(os.Stderr)
	}

	return base.Level(level).With().Timestamp().Logger()
}

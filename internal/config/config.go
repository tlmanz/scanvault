package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/tlmanz/goconf"
)

// Config holds all runtime configuration loaded from environment variables.
//
// Struct tags:
//   - env        : environment variable name
//   - envDefault : fallback value when the variable is absent
//   - hush       : "mask" or "hide" controls the printed config table
type Config struct {
	// HTTP server
	ServerPort   int           `env:"SERVER_PORT"        envDefault:"8080"`
	LogLevel     string        `env:"LOG_LEVEL"          envDefault:"info"`
	LogFormat    string        `env:"LOG_FORMAT"          envDefault:"json"`
	ReadTimeout  time.Duration `env:"HTTP_READ_TIMEOUT"  envDefault:"15s"`
	WriteTimeout time.Duration `env:"HTTP_WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout  time.Duration `env:"HTTP_IDLE_TIMEOUT"  envDefault:"60s"`

	// Database connection
	DatabaseURL string `env:"DATABASE_URL" hush:"mask"`

	// pgx connection pool tuning - all optional with production-ready defaults.
	DBMaxConns          int           `env:"DB_MAX_CONNS"           envDefault:"25"`
	DBMinConns          int           `env:"DB_MIN_CONNS"           envDefault:"2"`
	DBMaxConnLifetime   time.Duration `env:"DB_MAX_CONN_LIFETIME"   envDefault:"30m"`
	DBMaxConnIdleTime   time.Duration `env:"DB_MAX_CONN_IDLE_TIME"  envDefault:"5m"`
	DBHealthCheckPeriod time.Duration `env:"DB_HEALTH_CHECK_PERIOD" envDefault:"1m"`

	// Cleanup worker - all optional; zero values disable the feature.
	CleanupInterval     time.Duration `env:"CLEANUP_INTERVAL"      envDefault:"1h"`
	CleanupMaxAge       time.Duration `env:"CLEANUP_MAX_AGE"       envDefault:"0"`
	CleanupKeepPerImage int           `env:"CLEANUP_KEEP_PER_IMAGE" envDefault:"0"`
}

// Register implements goconf.Configer - parses environment variables into the Config struct.
func (c *Config) Register() error {
	return env.Parse(c)
}

// Validate implements goconf.Validater - enforces required fields and sane constraints.
func (c *Config) Validate() error {
	if c.DatabaseURL == "" {
		return errors.New("DATABASE_URL environment variable is required")
	}
	if c.DBMaxConns < 1 {
		return errors.New("DB_MAX_CONNS must be at least 1")
	}
	if c.DBMinConns < 0 {
		return errors.New("DB_MIN_CONNS must be non-negative")
	}
	if c.DBMinConns > c.DBMaxConns {
		return errors.New("DB_MIN_CONNS must be <= DB_MAX_CONNS")
	}
	switch c.LogFormat {
	case "json", "console":
		// valid
	default:
		return errors.New("LOG_FORMAT must be 'json' or 'console'")
	}
	if c.CleanupMaxAge == 0 && c.CleanupKeepPerImage == 0 {
		// Cleanup is fully disabled - that's fine.
		return nil
	}
	if c.CleanupInterval <= 0 {
		return errors.New("CLEANUP_INTERVAL must be > 0 when cleanup is enabled")
	}
	return nil
}

// Print implements goconf.Printer - returns the struct for the config table display.
func (c *Config) Print() interface{} {
	return c
}

// ServerAddress returns the formatted ":port" string for the HTTP server.
func (c *Config) ServerAddress() string {
	return fmt.Sprintf(":%d", c.ServerPort)
}

// Load reads all settings from environment variables via goconf and returns a
// validated *Config. An error is returned if required fields are absent or
// validation fails; on success goconf also prints a masked config table to stdout.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := goconf.Load(cfg); err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	return cfg, nil
}

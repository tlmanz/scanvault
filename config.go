// Package scanvault provides an embeddable Trivy scan ingestor service.
//
// Basic usage - standalone server:
//
//	srv, err := scanvault.New(ctx, scanvault.Config{DatabaseURL: os.Getenv("DATABASE_URL")})
//	if err != nil { log.Fatal(err) }
//	srv.Start(ctx)
//
// Mount on an existing router:
//
//	srv, _ := scanvault.New(ctx, scanvault.Config{DatabaseURL: dsn})
//	mux.Handle("/trivy/", http.StripPrefix("/trivy", srv.Handler()))
package scanvault

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	internalcfg "github.com/tlmanz/scanvault/internal/config"
)

// Config is the public configuration for a ScanVault server.
// All fields are optional except DatabaseURL when DBPool is not provided.
type Config struct {
	// DatabaseURL is the PostgreSQL DSN.
	// Required when DBPool is not provided.
	// e.g. "postgres://user:pass@localhost:5432/scanvault?sslmode=disable"
	DatabaseURL string

	// ServerPort is the HTTP listen port used by Start(). Default: 8080.
	ServerPort int

	// LogLevel controls verbosity. Accepted: debug, info, warn, error. Default: info.
	LogLevel string
	// LogFormat controls output format. Accepted: json, console. Default: json.
	LogFormat string

	// HTTP server timeouts (defaults: Read/Write 15s, Idle 60s).
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// pgx connection pool settings (see envvar defaults in .env.example).
	DBMaxConns          int
	DBMinConns          int
	DBMaxConnLifetime   time.Duration
	DBMaxConnIdleTime   time.Duration
	DBHealthCheckPeriod time.Duration

	// Cleanup worker - both policies are optional; zero values disable them.
	// CleanupInterval controls how often the worker runs. Default: 1h.
	CleanupInterval time.Duration
	// CleanupMaxAge deletes scans older than this duration (e.g. 72h). 0 = disabled.
	CleanupMaxAge time.Duration
	// CleanupKeepPerImage keeps only the N most recent scans per image. 0 = disabled.
	CleanupKeepPerImage int

	// Logger is an optional zerolog.Logger. When nil, one is built from
	// LogLevel and LogFormat.
	Logger *zerolog.Logger

	// DBPool is an optional externally managed pgx pool.
	// When set, New() uses this pool directly and does not create a new one
	// from DatabaseURL.
	DBPool *pgxpool.Pool
}

func (c *Config) applyDefaults() {
	if c.ServerPort == 0 {
		c.ServerPort = 8080
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.LogFormat == "" {
		c.LogFormat = "json"
	}
	if c.DBMaxConns == 0 {
		c.DBMaxConns = 25
	}
	if c.DBMinConns == 0 {
		c.DBMinConns = 2
	}
	if c.DBMaxConnLifetime == 0 {
		c.DBMaxConnLifetime = 30 * time.Minute
	}
	if c.DBMaxConnIdleTime == 0 {
		c.DBMaxConnIdleTime = 5 * time.Minute
	}
	if c.DBHealthCheckPeriod == 0 {
		c.DBHealthCheckPeriod = time.Minute
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 15 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 15 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 60 * time.Second
	}
	if c.CleanupInterval == 0 {
		c.CleanupInterval = time.Hour
	}
}

// toInternal converts the public Config into the internal config struct
// used by the db package for pool configuration.
func (c *Config) toInternal() *internalcfg.Config {
	return &internalcfg.Config{
		DatabaseURL:         c.DatabaseURL,
		ServerPort:          c.ServerPort,
		LogLevel:            c.LogLevel,
		LogFormat:           c.LogFormat,
		ReadTimeout:         c.ReadTimeout,
		WriteTimeout:        c.WriteTimeout,
		IdleTimeout:         c.IdleTimeout,
		DBMaxConns:          c.DBMaxConns,
		DBMinConns:          c.DBMinConns,
		DBMaxConnLifetime:   c.DBMaxConnLifetime,
		DBMaxConnIdleTime:   c.DBMaxConnIdleTime,
		DBHealthCheckPeriod: c.DBHealthCheckPeriod,
	}
}

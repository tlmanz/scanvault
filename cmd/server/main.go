package main

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/tlmanz/scanvault"
	"github.com/tlmanz/scanvault/internal/config"
)

func main() {
	// Load config from environment variables (goconf prints masked table on startup).
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}

	// Keep release-mode choice at the executable boundary instead of the library.
	gin.SetMode(gin.ReleaseMode)

	// Build and start the server using the public API.
	// LogLevel and LogFormat drive the zerolog logger built inside New().
	srv, err := scanvault.New(context.Background(), scanvault.Config{
		DatabaseURL:         cfg.DatabaseURL,
		ServerPort:          cfg.ServerPort,
		LogLevel:            cfg.LogLevel,
		LogFormat:           cfg.LogFormat,
		ReadTimeout:         cfg.ReadTimeout,
		WriteTimeout:        cfg.WriteTimeout,
		IdleTimeout:         cfg.IdleTimeout,
		DBMaxConns:          cfg.DBMaxConns,
		DBMinConns:          cfg.DBMinConns,
		DBMaxConnLifetime:   cfg.DBMaxConnLifetime,
		DBMaxConnIdleTime:   cfg.DBMaxConnIdleTime,
		DBHealthCheckPeriod: cfg.DBHealthCheckPeriod,
		CleanupInterval:     cfg.CleanupInterval,
		CleanupMaxAge:       cfg.CleanupMaxAge,
		CleanupKeepPerImage: cfg.CleanupKeepPerImage,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialise server")
	}

	if err := srv.Start(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("server error")
	}
}

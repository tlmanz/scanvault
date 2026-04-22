package main

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/tlmanz/scanvault/internal/config"
	"github.com/tlmanz/scanvault/internal/service"
)

func main() {
	// Load config from environment variables (goconf prints masked table on startup).
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}

	// Keep release-mode choice at the executable boundary instead of the library.
	gin.SetMode(gin.ReleaseMode)

	// Build and start the standalone service.
	srv, err := service.New(context.Background(), cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialise server")
	}

	if err := srv.Start(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("server error")
	}
}

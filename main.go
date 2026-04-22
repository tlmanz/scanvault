package main

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/tlmanz/scanvault/infra"
	"github.com/tlmanz/scanvault/presentation/rest"
)

func main() {
	// Load and validate all configuration from environment variables.
	cfg, err := infra.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}

	ctx := context.Background()

	// Resolve all dependencies into the IoC container.
	container, err := infra.NewResolvedContainer(ctx, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialise container")
	}
	defer container.Destroy()

	// Build the HTTP server (wires controllers, routes, and the cleanup worker).
	server := rest.NewServer(container)

	// Run until an OS signal or context cancellation.
	shutdownCtx, cancel := context.WithCancel(ctx)
	go func() {
		infra.WaitForShutdown(ctx)
		cancel()
	}()

	if err := server.Start(shutdownCtx); err != nil {
		container.Logger.Fatal().Err(err).Msg("server error")
	}
}

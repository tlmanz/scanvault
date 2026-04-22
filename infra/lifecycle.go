package infra

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// WaitForShutdown blocks until an OS interrupt/term signal is received or
// the given context is cancelled. The caller is responsible for any cleanup
// after this function returns.
func WaitForShutdown(ctx context.Context) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)

	select {
	case <-ctx.Done():
	case <-quit:
	}
}

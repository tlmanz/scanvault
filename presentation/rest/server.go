package rest

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tlmanz/scanvault/infra"
)

// Server wraps the HTTP server and its dependencies.
type Server struct {
	container *infra.Container
	httpSrv   *http.Server
}

// NewServer builds the gin router, wires controllers, and returns a ready Server.
func NewServer(c *infra.Container) *Server {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())

	h := NewScanController(c.ScanUseCases, c.Logger)
	RegisterRoutes(router, h, true, "")

	return &Server{
		container: c,
		httpSrv: &http.Server{
			Addr:         c.Config.ServerAddress(),
			Handler:      router,
			ReadTimeout:  c.Config.ReadTimeout,
			WriteTimeout: c.Config.WriteTimeout,
			IdleTimeout:  c.Config.IdleTimeout,
		},
	}
}

// Start begins serving HTTP and starts the cleanup worker (if enabled).
// It blocks until ctx is cancelled, then performs a graceful shutdown.
func (s *Server) Start(ctx context.Context) error {
	s.container.Logger.Info().Msg("scanvault: start requested")

	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()

	if s.container.CleanupWorker != nil {
		s.container.Logger.Debug().Msg("scanvault: starting cleanup worker")
		s.container.CleanupWorker.Start(workerCtx)
	}

	errCh := make(chan error, 1)
	go func() {
		s.container.Logger.Info().Str("addr", s.container.Config.ServerAddress()).Msg("scanvault: service started")
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		s.container.Logger.Info().Err(ctx.Err()).Msg("scanvault: shutdown requested by context")
	case err := <-errCh:
		cancelWorkers()
		return err
	}

	s.container.Logger.Info().Msg("scanvault: shutting down")
	cancelWorkers()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.httpSrv.Shutdown(shutdownCtx); err != nil {
		return err
	}

	s.container.Logger.Info().Msg("scanvault: shutdown complete")
	return nil
}

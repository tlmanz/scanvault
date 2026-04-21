package scanvault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/tlmanz/scanvault/internal/db"
	"github.com/tlmanz/scanvault/internal/handlers"
	"github.com/tlmanz/scanvault/internal/repository"
	"github.com/tlmanz/scanvault/internal/worker"
)

// Server is a fully initialised ScanVault service.
// Obtain one via New().
type Server struct {
	cfg       Config
	router    *gin.Engine
	logger    zerolog.Logger
	cleaner   *worker.Cleaner // nil when cleanup is disabled
	pool      *pgxpool.Pool
	ownsPool  bool
	closeOnce sync.Once
}

// New creates a new ScanVault Server. It connects to PostgreSQL, runs any
// pending goose migrations, and wires up all HTTP handlers.
//
// The ctx is used only for the initial DB connection; it is not held
// beyond New(). Cancel it to abort startup.
func New(ctx context.Context, cfg Config, opts ...Option) (*Server, error) {
	cfg.applyDefaults()

	for _, opt := range opts {
		opt(&cfg)
	}

	logger := buildLogger(cfg)
	logger.Debug().Msg("scanvault: initialising server")

	var (
		pool     *pgxpool.Pool
		ownsPool bool
		err      error
	)

	if cfg.DBPool != nil {
		logger.Info().Msg("scanvault: using provided database pool")
		pool = cfg.DBPool
	} else {
		if cfg.DatabaseURL == "" {
			return nil, errors.New("scanvault: Config.DatabaseURL is required when WithDBPool is not used")
		}

		logger.Info().Msg("scanvault: creating database pool")
		pool, err = db.New(ctx, cfg.toInternal())
		if err != nil {
			return nil, fmt.Errorf("scanvault: connecting to database: %w", err)
		}
		ownsPool = true
		logger.Info().Msg("scanvault: database pool ready")
	}

	migrationsStarted := time.Now()
	logger.Info().Msg("scanvault: running migrations")
	if err := runMigrations(pool); err != nil {
		if ownsPool {
			logger.Info().Msg("scanvault: closing owned database pool after migration failure")
			pool.Close()
		}
		return nil, fmt.Errorf("scanvault: running migrations: %w", err)
	}
	logger.Info().Dur("duration", time.Since(migrationsStarted)).Msg("scanvault: migrations complete")

	repo := repository.New(pool)

	router := gin.New()
	router.Use(gin.Recovery())

	h := handlers.New(repo, logger)
	router.GET("/health", h.HealthCheck)
	router.POST("/scans", h.CreateScan)
	router.GET("/scans", h.ListScans)
	router.GET("/scans/all", h.ListAllScans)
	router.GET("/scans/:id/vulnerabilities", h.GetScanVulnerabilities)
	router.GET("/scans/latest", h.GetLatestScan)
	router.GET("/analytics/vulnerabilities/summary", h.GetVulnerabilitySummary)
	router.GET("/analytics/vulnerabilities/trends", h.GetVulnerabilityTrends)
	router.GET("/analytics/vulnerabilities/top-cves", h.GetTopCVEs)
	router.GET("/analytics/vulnerabilities/cve/:cve_id/images", h.GetCVEAffectedImages)
	router.GET("/analytics/vulnerabilities/fixable", h.GetFixableSummary)

	// Build the cleanup worker if at least one policy is enabled.
	var cleaner *worker.Cleaner
	if cfg.CleanupMaxAge > 0 || cfg.CleanupKeepPerImage > 0 {
		logger.Info().
			Dur("interval", cfg.CleanupInterval).
			Dur("max_age", cfg.CleanupMaxAge).
			Int("keep_per_image", cfg.CleanupKeepPerImage).
			Msg("scanvault: cleanup worker enabled")

		cleaner = worker.New(worker.CleanupConfig{
			Interval:     cfg.CleanupInterval,
			MaxAge:       cfg.CleanupMaxAge,
			KeepPerImage: cfg.CleanupKeepPerImage,
		}, repo, logger)
	} else {
		logger.Info().Msg("scanvault: cleanup worker disabled")
	}

	logger.Info().Int("port", cfg.ServerPort).Msg("scanvault: server initialised")

	return &Server{
		cfg:      cfg,
		router:   router,
		logger:   logger,
		cleaner:  cleaner,
		pool:     pool,
		ownsPool: ownsPool,
	}, nil
}

// Handler returns the http.Handler for the ScanVault API.
// Use this to mount ScanVault under a path prefix in an existing HTTP server:
//
//	mux.Handle("/scans/", http.StripPrefix("/scans", srv.Handler()))
func (s *Server) Handler() http.Handler {
	return s.router
}

// Close releases resources owned by this Server.
// It is safe to call multiple times.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.logger.Debug().Msg("scanvault: closing server resources")
		if s.ownsPool && s.pool != nil {
			s.logger.Info().Msg("scanvault: closing owned database pool")
			s.pool.Close()
		} else {
			s.logger.Debug().Msg("scanvault: no owned pool to close")
		}
	})
	return nil
}

// Start runs a standalone HTTP server and blocks until ctx is cancelled or
// SIGINT/SIGTERM is received, then shuts down gracefully.
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info().Msg("scanvault: start requested")

	// Create a cancellable child context for background workers.
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()

	if s.cleaner != nil {
		s.logger.Debug().Msg("scanvault: starting cleanup worker")
		s.cleaner.Start(workerCtx)
	}

	addr := fmt.Sprintf(":%d", s.cfg.ServerPort)

	srv := &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: s.cfg.WriteTimeout,
		IdleTimeout:  s.cfg.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info().Str("addr", addr).Msg("scanvault: server started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error().Err(err).Str("addr", addr).Msg("scanvault: listen failed")
			errCh <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)

	select {
	case <-ctx.Done():
		s.logger.Info().Err(ctx.Err()).Msg("scanvault: shutdown requested by context")
	case <-quit:
		s.logger.Info().Msg("scanvault: shutdown requested by signal")
	case err := <-errCh:
		s.logger.Error().Err(err).Msg("scanvault: server loop exited with error")
		cancelWorkers()
		_ = s.Close()
		return err
	}

	s.logger.Info().Msg("scanvault: shutting down")
	// cancelWorkers() stops the cleanup goroutine before we drain HTTP.
	cancelWorkers()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		s.logger.Error().Err(err).Msg("scanvault: graceful shutdown failed")
		_ = s.Close()
		return err
	}

	s.logger.Info().Msg("scanvault: shutdown complete")
	return s.Close()
}

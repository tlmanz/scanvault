package service

import (
	"context"
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
	"github.com/tlmanz/scanvault/internal/config"
	"github.com/tlmanz/scanvault/internal/db"
	"github.com/tlmanz/scanvault/internal/handlers"
	"github.com/tlmanz/scanvault/internal/repository"
	"github.com/tlmanz/scanvault/internal/worker"
)

type Server struct {
	cfg       *config.Config
	router    *gin.Engine
	logger    zerolog.Logger
	cleaner   *worker.Cleaner
	pool      *pgxpool.Pool
	closeOnce sync.Once
}

func New(ctx context.Context, cfg *config.Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("service config is required")
	}

	logger := buildLogger(cfg)
	logger.Debug().Msg("scanvault: initialising service")

	logger.Info().Msg("scanvault: creating database pool")
	pool, err := db.New(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	logger.Info().Msg("scanvault: database pool ready")

	migrationsStarted := time.Now()
	logger.Info().Msg("scanvault: running migrations")
	if err := runMigrations(pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
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

	logger.Info().Int("port", cfg.ServerPort).Msg("scanvault: service initialised")

	return &Server{
		cfg:     cfg,
		router:  router,
		logger:  logger,
		cleaner: cleaner,
		pool:    pool,
	}, nil
}

func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.logger.Debug().Msg("scanvault: closing service resources")
		if s.pool != nil {
			s.pool.Close()
		}
	})
}

func (s *Server) Start(ctx context.Context) error {
	s.logger.Info().Msg("scanvault: start requested")

	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()

	if s.cleaner != nil {
		s.logger.Debug().Msg("scanvault: starting cleanup worker")
		s.cleaner.Start(workerCtx)
	}

	srv := &http.Server{
		Addr:         s.cfg.ServerAddress(),
		Handler:      s.router,
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: s.cfg.WriteTimeout,
		IdleTimeout:  s.cfg.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info().Str("addr", s.cfg.ServerAddress()).Msg("scanvault: service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
		cancelWorkers()
		s.Close()
		return err
	}

	s.logger.Info().Msg("scanvault: shutting down")
	cancelWorkers()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		s.Close()
		return err
	}

	s.logger.Info().Msg("scanvault: shutdown complete")
	s.Close()
	return nil
}

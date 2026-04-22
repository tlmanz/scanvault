package infra

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/tlmanz/scanvault/domain/usecases"
	postgres "github.com/tlmanz/scanvault/persistence/postgres"
)

// Container is a simple implementation of a dependency inversion container.
//
// Dependencies are resolved manually — there is no fancy DI framework.
// This makes startup explicit, testable, and easy to trace.
type Container struct {
	Config        *Config
	Logger        zerolog.Logger
	pool          *pgxpool.Pool
	ScanRepo      *postgres.ScanRepository
	ScanUseCases  *usecases.ScanUseCases
	CleanupWorker *usecases.Cleaner
}

// NewResolvedContainer builds and wires all dependencies, returning a ready-to-use
// Container. Call Destroy() when shutting down to release resources.
func NewResolvedContainer(ctx context.Context, cfg *Config) (*Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("container: config is required")
	}

	c := &Container{Config: cfg}

	// ── Logger ──────────────────────────────────────────────────────────────
	c.Logger = NewLogger(cfg)
	c.Logger.Debug().Msg("scanvault: initialising container")

	// ── Database pool ────────────────────────────────────────────────────────
	c.Logger.Info().Msg("scanvault: creating database pool")
	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL, postgres.PoolConfig{
		MaxConns:          int32(cfg.DBMaxConns),
		MinConns:          int32(cfg.DBMinConns),
		MaxConnLifetime:   cfg.DBMaxConnLifetime,
		MaxConnIdleTime:   cfg.DBMaxConnIdleTime,
		HealthCheckPeriod: cfg.DBHealthCheckPeriod,
	})
	if err != nil {
		return nil, fmt.Errorf("container: connecting to database: %w", err)
	}
	c.pool = pool
	c.Logger.Info().Msg("scanvault: database pool ready")

	// ── Migrations ───────────────────────────────────────────────────────────
	c.Logger.Info().Msg("scanvault: running migrations")
	if err := postgres.RunMigrations(pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("container: running migrations: %w", err)
	}
	c.Logger.Info().Msg("scanvault: migrations complete")

	// ── Repository (implements all four boundary interfaces) ─────────────────
	c.ScanRepo = postgres.NewScanRepository(pool)

	// ── Use cases ────────────────────────────────────────────────────────────
	c.ScanUseCases = usecases.NewScanUseCases(c.ScanRepo, c.ScanRepo, c.ScanRepo)

	// ── Cleanup worker (optional) ────────────────────────────────────────────
	if cfg.CleanupMaxAge > 0 || cfg.CleanupKeepPerImage > 0 {
		c.Logger.Info().
			Dur("interval", cfg.CleanupInterval).
			Dur("max_age", cfg.CleanupMaxAge).
			Int("keep_per_image", cfg.CleanupKeepPerImage).
			Msg("scanvault: cleanup worker enabled")

		c.CleanupWorker = usecases.NewCleaner(usecases.CleanupConfig{
			Interval:     cfg.CleanupInterval,
			MaxAge:       cfg.CleanupMaxAge,
			KeepPerImage: cfg.CleanupKeepPerImage,
		}, c.ScanRepo, c.Logger)
	} else {
		c.Logger.Info().Msg("scanvault: cleanup worker disabled")
	}

	c.Logger.Info().Int("port", cfg.ServerPort).Msg("scanvault: container ready")
	return c, nil
}

// Destroy releases all resources held by the container (database pool, etc.).
// Safe to call multiple times.
func (c *Container) Destroy() {
	if c.pool != nil {
		c.Logger.Debug().Msg("scanvault: closing database pool")
		c.pool.Close()
	}
}

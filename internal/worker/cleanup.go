package worker

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// CleanupConfig holds the retention policies for the cleanup worker.
// Zero values disable the corresponding policy.
type CleanupConfig struct {
	// Interval between cleanup runs. Default: 1h.
	Interval time.Duration

	// MaxAge deletes scans older than this duration (e.g. 72h).
	// 0 disables age-based cleanup.
	MaxAge time.Duration

	// KeepPerImage retains only the N most recent scans per image name.
	// 0 disables count-based cleanup.
	KeepPerImage int
}

// Store is the subset of repository methods the cleaner needs.
type Store interface {
	// DeleteOlderThan removes all scans older than age.
	DeleteOlderThan(ctx context.Context, age time.Duration) (int64, error)
	// DeleteExcessPerImage keeps only the <keep> newest scans per image name.
	DeleteExcessPerImage(ctx context.Context, keep int) (int64, error)
	// DeleteExcessAndOld deletes scans that fail BOTH policies: older than age
	// AND ranked outside the top <keep> for their image. Use this when both
	// policies are active so that recent-enough scans are never wiped.
	DeleteExcessAndOld(ctx context.Context, age time.Duration, keep int) (int64, error)
}

// Cleaner is a background worker that periodically removes old scan records.
type Cleaner struct {
	cfg    CleanupConfig
	store  Store
	logger zerolog.Logger
	stop   chan struct{}
	stopMu sync.Once
}

// New creates a new Cleaner. Call Start() to begin the background loop.
func New(cfg CleanupConfig, store Store, logger zerolog.Logger) *Cleaner {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Hour
	}
	return &Cleaner{
		cfg:    cfg,
		store:  store,
		logger: logger,
		stop:   make(chan struct{}),
	}
}

// Start runs the cleanup loop in a goroutine until ctx is cancelled or Stop() is called.
func (c *Cleaner) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(c.cfg.Interval)
		defer ticker.Stop()

		c.logger.Info().
			Dur("interval", c.cfg.Interval).
			Dur("max_age", c.cfg.MaxAge).
			Int("keep_per_image", c.cfg.KeepPerImage).
			Msg("cleanup worker started")

		for {
			select {
			case <-ticker.C:
				c.run(ctx)
			case <-ctx.Done():
				c.logger.Info().Msg("cleanup worker stopped")
				return
			case <-c.stop:
				c.logger.Info().Msg("cleanup worker stopped")
				return
			}
		}
	}()
}

// Stop signals the cleanup worker to exit.
func (c *Cleaner) Stop() {
	c.stopMu.Do(func() {
		close(c.stop)
	})
}

// run executes one cleanup pass.
//
// Policy interaction:
//   - Only MaxAge set    → delete all scans older than MaxAge.
//   - Only KeepPerImage  → delete all scans beyond top-N per image.
//   - Both set           → delete only scans that are BOTH older than MaxAge
//     AND outside top-N. A scan older than MaxAge but still in the top-N
//     for its image is preserved.
func (c *Cleaner) run(ctx context.Context) {
	bothActive := c.cfg.MaxAge > 0 && c.cfg.KeepPerImage > 0

	switch {
	case bothActive:
		// Combined query: per-image retention takes precedence over age.
		n, err := c.store.DeleteExcessAndOld(ctx, c.cfg.MaxAge, c.cfg.KeepPerImage)
		if err != nil {
			c.logger.Error().Err(err).Msg("cleanup: combined deletion failed")
		} else if n > 0 {
			c.logger.Info().Int64("deleted", n).
				Dur("max_age", c.cfg.MaxAge).
				Int("keep_per_image", c.cfg.KeepPerImage).
				Msg("cleanup: removed old excess scans")
		} else {
			c.logger.Debug().
				Dur("max_age", c.cfg.MaxAge).
				Int("keep_per_image", c.cfg.KeepPerImage).
				Msg("cleanup: no scans matched combined policy")
		}

	case c.cfg.MaxAge > 0:
		n, err := c.store.DeleteOlderThan(ctx, c.cfg.MaxAge)
		if err != nil {
			c.logger.Error().Err(err).Msg("cleanup: age-based deletion failed")
		} else if n > 0 {
			c.logger.Info().Int64("deleted", n).Dur("max_age", c.cfg.MaxAge).
				Msg("cleanup: removed old scans")
		} else {
			c.logger.Debug().Dur("max_age", c.cfg.MaxAge).
				Msg("cleanup: no scans matched age policy")
		}

	case c.cfg.KeepPerImage > 0:
		n, err := c.store.DeleteExcessPerImage(ctx, c.cfg.KeepPerImage)
		if err != nil {
			c.logger.Error().Err(err).Msg("cleanup: per-image deletion failed")
		} else if n > 0 {
			c.logger.Info().Int64("deleted", n).Int("keep_per_image", c.cfg.KeepPerImage).
				Msg("cleanup: trimmed excess scans per image")
		} else {
			c.logger.Debug().Int("keep_per_image", c.cfg.KeepPerImage).
				Msg("cleanup: no scans matched per-image policy")
		}
	}
}

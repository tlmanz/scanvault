package infra_test

import (
	"testing"
	"time"

	"github.com/tlmanz/scanvault/infra"
)

func TestLoad_Defaults(t *testing.T) {
	// Make this test hermetic even when `make` exports values from .env.
	t.Setenv("SERVER_PORT", "")
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("LOG_FORMAT", "")
	t.Setenv("HTTP_READ_TIMEOUT", "")
	t.Setenv("HTTP_WRITE_TIMEOUT", "")
	t.Setenv("HTTP_IDLE_TIMEOUT", "")
	t.Setenv("DB_MAX_CONNS", "")
	t.Setenv("DB_MIN_CONNS", "")
	t.Setenv("DB_MAX_CONN_LIFETIME", "")
	t.Setenv("DB_MAX_CONN_IDLE_TIME", "")
	t.Setenv("DB_HEALTH_CHECK_PERIOD", "")
	t.Setenv("CLEANUP_INTERVAL", "")
	t.Setenv("CLEANUP_MAX_AGE", "")
	t.Setenv("CLEANUP_KEEP_PER_IMAGE", "")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	// All other vars intentionally absent - defaults should apply.

	cfg, err := infra.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ServerPort != 8080 {
		t.Errorf("ServerPort: want 8080, got %d", cfg.ServerPort)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel: want info, got %s", cfg.LogLevel)
	}
	if cfg.ReadTimeout != 15*time.Second {
		t.Errorf("ReadTimeout: want 15s, got %v", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 15*time.Second {
		t.Errorf("WriteTimeout: want 15s, got %v", cfg.WriteTimeout)
	}
	if cfg.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout: want 60s, got %v", cfg.IdleTimeout)
	}
	if cfg.DBMaxConns != 25 {
		t.Errorf("DBMaxConns: want 25, got %d", cfg.DBMaxConns)
	}
	if cfg.DBMinConns != 2 {
		t.Errorf("DBMinConns: want 2, got %d", cfg.DBMinConns)
	}
	if cfg.DBMaxConnLifetime != 30*time.Minute {
		t.Errorf("DBMaxConnLifetime: want 30m, got %v", cfg.DBMaxConnLifetime)
	}
}

func TestLoad_Overrides(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	t.Setenv("SERVER_PORT", "9090")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("HTTP_READ_TIMEOUT", "30s")
	t.Setenv("DB_MAX_CONNS", "50")
	t.Setenv("DB_MIN_CONNS", "5")

	cfg, err := infra.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ServerPort != 9090 {
		t.Errorf("ServerPort: want 9090, got %d", cfg.ServerPort)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel: want debug, got %s", cfg.LogLevel)
	}
	if cfg.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout: want 30s, got %v", cfg.ReadTimeout)
	}
	if cfg.DBMaxConns != 50 {
		t.Errorf("DBMaxConns: want 50, got %d", cfg.DBMaxConns)
	}
}

func TestLoad_MissingDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")

	_, err := infra.Load()
	if err == nil {
		t.Fatal("expected error when DATABASE_URL is empty, got nil")
	}
}

func TestLoad_InvalidMinMaxConns(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	t.Setenv("DB_MIN_CONNS", "100")
	t.Setenv("DB_MAX_CONNS", "10")

	_, err := infra.Load()
	if err == nil {
		t.Fatal("expected error when DB_MIN_CONNS > DB_MAX_CONNS, got nil")
	}
}

func TestServerAddress(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	t.Setenv("SERVER_PORT", "3000")

	cfg, err := infra.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerAddress() != ":3000" {
		t.Errorf("ServerAddress: want :3000, got %s", cfg.ServerAddress())
	}
}

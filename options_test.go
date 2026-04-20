package scanvault

import "testing"

func TestWithDBPoolSetsConfigPool(t *testing.T) {
	var cfg Config

	WithDBPool(nil)(&cfg)

	if cfg.DBPool != nil {
		t.Fatal("expected DBPool to be nil when option is called with nil")
	}
}

func TestRunMigrationsNilPool(t *testing.T) {
	err := runMigrations(nil)
	if err == nil {
		t.Fatal("expected error for nil pool, got nil")
	}
}

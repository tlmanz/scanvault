package scanvault

import (
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	svmigrations "github.com/tlmanz/scanvault/migrations"
)

var (
	gooseInitOnce sync.Once
	gooseInitErr  error
)

func initGoose() error {
	gooseInitOnce.Do(func() {
		goose.SetBaseFS(svmigrations.FS)
		goose.SetLogger(goose.NopLogger())
		gooseInitErr = goose.SetDialect("postgres")
	})

	if gooseInitErr != nil {
		return fmt.Errorf("setting dialect: %w", gooseInitErr)
	}

	return nil
}

// runMigrations runs all pending goose migrations using the embedded SQL FS.
func runMigrations(pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("nil database pool")
	}

	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()

	if err := initGoose(); err != nil {
		return err
	}
	if err := goose.Up(sqlDB, "."); err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}

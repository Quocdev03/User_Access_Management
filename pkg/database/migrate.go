package database

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migrate_mysql "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/quocdev03/user-access-management/internal/config"
)

func RunMigrations(
	cfg config.DatabaseConfig,
	migrationsPath string,
	appEnv string,
) (resultErr error) {
	mysqlCfg, err := newMySQLConfig(cfg, true)
	if err != nil {
		return err
	}
	db, err := sql.Open("mysql", mysqlCfg.FormatDSN())
	if err != nil {
		return fmt.Errorf("không thể kết nối database cho migration: %w", err)
	}

	driver, err := migrate_mysql.WithInstance(db, &migrate_mysql.Config{})
	if err != nil {
		resultErr := fmt.Errorf("không thể khởi tạo migration driver: %w", err)
		if closeErr := db.Close(); closeErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("close migration database: %w", closeErr),
			)
		}
		return resultErr
	}
	m, err := migrate.NewWithDatabaseInstance("file://"+migrationsPath, "mysql", driver)
	if err != nil {
		resultErr := fmt.Errorf("không thể khởi tạo migrate instance: %w", err)
		if closeErr := db.Close(); closeErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("close migration database: %w", closeErr),
			)
		}
		return resultErr
	}
	defer func() {
		sourceErr, databaseErr := m.Close()
		if sourceErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close migration source: %w", sourceErr))
		}
		if databaseErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("close migration driver: %w", databaseErr),
			)
		}
	}()

	version, dirty, err := m.Version()
	if err == nil && dirty {
		if appEnv == "production" {
			return fmt.Errorf(
				"database migration dirty ở version %d; production yêu cầu xử lý thủ công",
				version,
			)
		}
		if forceErr := m.Force(int(version) - 1); forceErr != nil {
			return fmt.Errorf("tự động force dirty database: %w", forceErr)
		}
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("chạy migration: %w", err)
	}
	return nil
}

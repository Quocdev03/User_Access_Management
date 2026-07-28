package database

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/config"
)

func ConnectMySQL(cfg config.DatabaseConfig) (*sqlx.DB, error) {
	mysqlCfg, err := newMySQLConfig(cfg, false)
	if err != nil {
		return nil, err
	}
	db, err := sqlx.Connect("mysql", mysqlCfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MySQL: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	return db, nil
}

package database

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

// File này mở MySQL connection pool từ cấu hình đã kiểm tra.

// ConnectMySQL mở connection pool và ping MySQL trước khi trả cho runtime.
func ConnectMySQL(opts MySQLOptions) (*sqlx.DB, error) {
	mysqlCfg, err := newMySQLConfig(opts, false)
	if err != nil {
		return nil, err
	}
	db, err := sqlx.Connect("mysql", mysqlCfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MySQL: %w", err)
	}

	db.SetMaxOpenConns(opts.MaxOpenConns)
	db.SetMaxIdleConns(opts.MaxIdleConns)
	db.SetConnMaxLifetime(opts.ConnMaxLifetime)
	db.SetConnMaxIdleTime(opts.ConnMaxIdleTime)

	return db, nil
}

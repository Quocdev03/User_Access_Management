//go:build integration

package database_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	migrateMySQL "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// File này kiểm chứng tích hợp migrate mfa integration với các dependency runtime liên quan.

// TestMFAMigrationCurrentData kiểm chứng kịch bản MFAMigrationCurrentData.
func TestMFAMigrationCurrentData(t *testing.T) {
	db, migrator, databaseName := mfaMigrationMigrator(
		t,
		"UAM_MFA_MIGRATION_CURRENT_DB_NAME",
	)

	if err := migrator.Migrate(30); err != nil {
		t.Fatalf("migrate current-data fixture to version 30: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO users (
			username, email, password_hash, full_name, phone, date_of_birth,
			status, lifecycle_state, email_verified, must_change_password,
			password_change_required, auth_version
		) VALUES (
			'mfa_existing', 'mfa_existing@example.test', 'hash',
			'MFA Existing', '0900000011', '1990-01-11',
			'active', 'active', TRUE, FALSE, FALSE, 7
		)`); err != nil {
		t.Fatalf("insert version-30 fixture: %v", err)
	}
	if err := migrator.Steps(1); err != nil {
		t.Fatalf("apply MFA expand migration: %v", err)
	}
	assertMFAMigrationSchema(t, db, databaseName)
	var existing int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM users WHERE username = 'mfa_existing' AND auth_version = 7`,
	).Scan(&existing); err != nil {
		t.Fatalf("check preserved current data: %v", err)
	}
	if existing != 1 {
		t.Fatalf("preserved current users = %d, want 1", existing)
	}
}

// TestMFAMigrationEmptyUp kiểm chứng kịch bản MFAMigrationEmptyUp.
func TestMFAMigrationEmptyUp(t *testing.T) {
	db, migrator, databaseName := mfaMigrationMigrator(
		t,
		"UAM_MFA_MIGRATION_EMPTY_DB_NAME",
	)
	if err := migrator.Migrate(31); err != nil {
		t.Fatalf("migrate empty database to MFA migration head: %v", err)
	}
	assertMFAMigrationSchema(t, db, databaseName)
}

// mfaMigrationMigrator tạo migrator bắt đầu tại schema ngay trước MFA phase.
func mfaMigrationMigrator(
	t *testing.T,
	databaseNameEnv string,
) (*sql.DB, *migrate.Migrate, string) {
	t.Helper()
	cfg := mysqlDriver.Config{
		User:                 os.Getenv("UAM_MIGRATION_TEST_DB_USER"),
		Passwd:               os.Getenv("UAM_MIGRATION_TEST_DB_PASSWORD"),
		Net:                  "tcp",
		Addr:                 os.Getenv("UAM_MIGRATION_TEST_DB_ADDR"),
		DBName:               os.Getenv(databaseNameEnv),
		Collation:            "utf8mb4_unicode_ci",
		ParseTime:            true,
		Loc:                  time.UTC,
		AllowNativePasswords: true,
		MultiStatements:      true,
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:3306"
	}
	if cfg.User == "" || cfg.DBName == "" {
		t.Skip("MFA migration integration database is not configured")
	}
	if !strings.HasPrefix(cfg.DBName, "uam_mfa_migration_test_") {
		t.Fatalf("refusing non-disposable database %q", cfg.DBName)
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open MFA migration database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	driver, err := migrateMySQL.WithInstance(db, &migrateMySQL.Config{})
	if err != nil {
		t.Fatalf("create MFA migration driver: %v", err)
	}
	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	migrator, err := migrate.NewWithDatabaseInstance(
		"file://"+filepath.ToSlash(migrationsPath),
		"mysql",
		driver,
	)
	if err != nil {
		t.Fatalf("create MFA migrator: %v", err)
	}
	t.Cleanup(func() {
		_, _ = migrator.Close()
	})
	return db, migrator, cfg.DBName
}

// assertMFAMigrationSchema kiểm tra bảng, index và constraint MFA sau migration.
func assertMFAMigrationSchema(t *testing.T, db *sql.DB, databaseName string) {
	t.Helper()
	var version uint
	var dirty bool
	if err := db.QueryRow(
		`SELECT version, dirty FROM schema_migrations LIMIT 1`,
	).Scan(&version, &dirty); err != nil {
		t.Fatalf("read MFA migration state: %v", err)
	}
	if version != 31 || dirty {
		t.Fatalf("schema state = version %d dirty=%t, want version 31 clean", version, dirty)
	}
	for _, table := range []string{"user_totp", "user_totp_recovery_codes"} {
		var count int
		if err := db.QueryRow(`
			SELECT COUNT(*)
			FROM information_schema.tables
			WHERE table_schema = ? AND table_name = ?`,
			databaseName,
			table,
		).Scan(&count); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("table %s count = %d, want 1", table, count)
		}
	}
	for _, column := range []string{
		"secret_ciphertext",
		"key_version",
		"last_used_step",
		"confirmed_at",
		"enabled_at",
	} {
		var count int
		if err := db.QueryRow(`
			SELECT COUNT(*)
			FROM information_schema.columns
			WHERE table_schema = ? AND table_name = 'user_totp'
			  AND column_name = ?`,
			databaseName,
			column,
		).Scan(&count); err != nil {
			t.Fatalf("check user_totp.%s: %v", column, err)
		}
		if count != 1 {
			t.Fatalf("user_totp.%s count = %d, want 1", column, count)
		}
	}
}

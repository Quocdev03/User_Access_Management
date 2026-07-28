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

func TestContractMigrationCurrentData(t *testing.T) {
	db, migrator, databaseName := contractMigrationMigrator(
		t,
		"UAM_CONTRACT_MIGRATION_CURRENT_DB_NAME",
	)
	if err := migrator.Migrate(31); err != nil {
		t.Fatalf("migrate contract fixture to version 31: %v", err)
	}
	insertContractMigrationFixture(t, db)

	if err := migrator.Up(); err != nil {
		t.Fatalf("apply contract migrations: %v", err)
	}
	assertContractMigrationSchema(t, db, databaseName)
	assertContractMigrationData(t, db)
}

func TestContractMigrationEmptyUp(t *testing.T) {
	db, migrator, databaseName := contractMigrationMigrator(
		t,
		"UAM_CONTRACT_MIGRATION_EMPTY_DB_NAME",
	)
	if err := migrator.Up(); err != nil {
		t.Fatalf("migrate empty database to contract head: %v", err)
	}
	assertContractMigrationSchema(t, db, databaseName)
}

func contractMigrationMigrator(
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
		t.Skip("contract migration integration database is not configured")
	}
	if !strings.HasPrefix(cfg.DBName, "uam_contract_migration_test_") {
		t.Fatalf("refusing non-disposable database %q", cfg.DBName)
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open contract migration database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	driver, err := migrateMySQL.WithInstance(db, &migrateMySQL.Config{})
	if err != nil {
		t.Fatalf("create contract migration driver: %v", err)
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
		t.Fatalf("create contract migrator: %v", err)
	}
	t.Cleanup(func() {
		_, _ = migrator.Close()
	})
	return db, migrator, cfg.DBName
}

func insertContractMigrationFixture(t *testing.T, db *sql.DB) {
	t.Helper()
	result, err := db.Exec(`
		INSERT INTO users (
			username, email, password_hash, full_name, phone, avatar_url,
			date_of_birth, status, lifecycle_state, email_verified,
			failed_login_attempts, locked_until, must_change_password,
			password_change_required, auth_version
		) VALUES (
			'contract_existing', 'contract_existing@example.test', 'hash',
			'Contract Existing', '0900000013', '/uploads/contract.png',
			'1990-01-13', 'active', 'active', TRUE, 0, NULL, FALSE, FALSE, 7
		)`)
	if err != nil {
		t.Fatalf("insert contract account fixture: %v", err)
	}
	userID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read contract account ID: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO user_profiles (
			user_id, full_name, phone, date_of_birth, avatar_object_key
		) VALUES (?, 'Contract Existing', '0900000013', '1990-01-13',
			'/uploads/contract.png')`,
		userID,
	); err != nil {
		t.Fatalf("insert contract profile fixture: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO sessions (
			user_id, token_hash, refresh_token_hash, current_refresh_hash,
			jti, access_jti, expires_at
		) VALUES (
			?, 'contract-access', 'contract-refresh', 'contract-refresh',
			'contract-jti', 'contract-jti', '2030-01-01'
		)`,
		userID,
	); err != nil {
		t.Fatalf("insert contract session fixture: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO otp_codes (
			user_id, code, type, attempts, is_used, expires_at
		) VALUES (
			?, 'contract-email-code', 'email_verification', 2, FALSE,
			'2030-01-01'
		)`,
		userID,
	); err != nil {
		t.Fatalf("insert contract OTP fixture: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO password_reset_tokens (
			user_id, token_hash, auth_version, is_used, expires_at
		) VALUES (?, 'contract-reset', NULL, FALSE, '2030-01-01')`,
		userID,
	); err != nil {
		t.Fatalf("insert contract reset fixture: %v", err)
	}
}

func assertContractMigrationSchema(
	t *testing.T,
	db *sql.DB,
	databaseName string,
) {
	t.Helper()
	var version uint
	var dirty bool
	if err := db.QueryRow(
		"SELECT version, dirty FROM schema_migrations LIMIT 1",
	).Scan(&version, &dirty); err != nil {
		t.Fatalf("read contract migration state: %v", err)
	}
	if version != 34 || dirty {
		t.Fatalf(
			"schema state = version %d dirty=%t, want version 34 clean",
			version,
			dirty,
		)
	}

	for _, column := range []struct {
		table string
		name  string
	}{
		{"users", "full_name"},
		{"users", "phone"},
		{"users", "avatar_url"},
		{"users", "date_of_birth"},
		{"users", "status"},
		{"users", "locked_until"},
		{"users", "must_change_password"},
		{"sessions", "token_hash"},
		{"sessions", "refresh_token_hash"},
		{"sessions", "jti"},
		{"sessions", "device_id"},
		{"password_reset_tokens", "is_used"},
	} {
		assertContractMigrationColumnCount(t, db, databaseName, column.table, column.name, 0)
	}
	for _, column := range []struct {
		table string
		name  string
	}{
		{"users", "lifecycle_state"},
		{"users", "password_change_required"},
		{"users", "auth_version"},
		{"sessions", "access_jti"},
		{"sessions", "current_refresh_hash"},
		{"password_reset_tokens", "auth_version"},
	} {
		var nullable string
		if err := db.QueryRow(`
			SELECT is_nullable
			FROM information_schema.columns
			WHERE table_schema = ? AND table_name = ? AND column_name = ?`,
			databaseName,
			column.table,
			column.name,
		).Scan(&nullable); err != nil {
			t.Fatalf("check %s.%s nullability: %v", column.table, column.name, err)
		}
		if nullable != "NO" {
			t.Fatalf("%s.%s is_nullable = %q, want NO", column.table, column.name, nullable)
		}
	}

	var otpTables int
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM information_schema.tables
		WHERE table_schema = ? AND table_name = 'otp_codes'`,
		databaseName,
	).Scan(&otpTables); err != nil {
		t.Fatalf("check removed otp_codes table: %v", err)
	}
	if otpTables != 0 {
		t.Fatalf("otp_codes table count = %d, want 0", otpTables)
	}
}

func assertContractMigrationColumnCount(
	t *testing.T,
	db *sql.DB,
	databaseName string,
	table string,
	column string,
	want int,
) {
	t.Helper()
	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM information_schema.columns
		WHERE table_schema = ? AND table_name = ? AND column_name = ?`,
		databaseName,
		table,
		column,
	).Scan(&count); err != nil {
		t.Fatalf("check column %s.%s: %v", table, column, err)
	}
	if count != want {
		t.Fatalf("column %s.%s count = %d, want %d", table, column, count, want)
	}
}

func assertContractMigrationData(t *testing.T, db *sql.DB) {
	t.Helper()
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM users u
		INNER JOIN user_profiles p ON p.user_id = u.id
		WHERE u.username = 'contract_existing'
		  AND u.lifecycle_state = 'active'
		  AND u.auth_version = 7
		  AND p.full_name = 'Contract Existing'
		  AND p.avatar_object_key = '/uploads/contract.png'`,
		1,
	)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM sessions
		WHERE current_refresh_hash = 'contract-refresh'
		  AND access_jti = 'contract-jti'`,
		1,
	)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM verification_challenges
		WHERE purpose = 'email_verification'
		  AND secret_hash = 'contract-email-code'
		  AND attempts = 2`,
		1,
	)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM password_reset_tokens
		WHERE token_hash = 'contract-reset'
		  AND auth_version = 7
		  AND consumed_at IS NOT NULL`,
		1,
	)
}

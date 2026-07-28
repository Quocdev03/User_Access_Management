//go:build integration

package database_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	migrateMySQL "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

func TestNeutralizeKnownBootstrapAdminMigration(t *testing.T) {
	cfg := mysqlDriver.Config{
		User:                 os.Getenv("UAM_MIGRATION_TEST_DB_USER"),
		Passwd:               os.Getenv("UAM_MIGRATION_TEST_DB_PASSWORD"),
		Net:                  "tcp",
		Addr:                 os.Getenv("UAM_MIGRATION_TEST_DB_ADDR"),
		DBName:               os.Getenv("UAM_BOOTSTRAP_MIGRATION_DB_NAME"),
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
		t.Skip("migration integration database is not configured")
	}
	if !strings.HasPrefix(cfg.DBName, "uam_bootstrap_migration_test_") {
		t.Fatalf("refusing non-disposable database %q", cfg.DBName)
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open migration database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	driver, err := migrateMySQL.WithInstance(db, &migrateMySQL.Config{})
	if err != nil {
		t.Fatalf("create migration driver: %v", err)
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
		t.Fatalf("create migrator: %v", err)
	}
	t.Cleanup(func() {
		_, _ = migrator.Close()
	})

	if err := migrator.Migrate(18); err != nil {
		t.Fatalf("migrate to version 18: %v", err)
	}

	const bootstrapLookup = `
		SELECT id
		FROM users
		WHERE username = 'admin_local'
		  AND email = 'admin@localhost.local'
		LIMIT 1`
	var bootstrapID uint64
	if err := db.QueryRow(bootstrapLookup).Scan(&bootstrapID); err != nil {
		t.Fatalf("load historical bootstrap user: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO audit_logs (user_id, action, status) VALUES (?, 'TEST_BOOTSTRAP_AUDIT', 'success')`,
		bootstrapID,
	); err != nil {
		t.Fatalf("insert bootstrap audit row: %v", err)
	}

	if err := migrator.Steps(1); err != nil {
		t.Fatalf("apply migration 19: %v", err)
	}
	assertUserCount(t, db, bootstrapLookup, 0)

	var anonymizedAuditCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM audit_logs WHERE action = 'TEST_BOOTSTRAP_AUDIT' AND user_id IS NULL`,
	).Scan(&anonymizedAuditCount); err != nil {
		t.Fatalf("count anonymized audit rows: %v", err)
	}
	if anonymizedAuditCount != 1 {
		t.Fatalf("anonymized audit rows = %d, want 1", anonymizedAuditCount)
	}

	if err := migrator.Steps(-1); err != nil {
		t.Fatalf("roll back migration 19 metadata: %v", err)
	}
	assertUserCount(t, db, bootstrapLookup, 0)

	if _, err := db.Exec(`
		INSERT INTO users (
			username, email, password_hash, full_name, phone, date_of_birth,
			status, email_verified
		) VALUES (
			'admin_local', 'admin@localhost.local', ?, 'Changed Administrator',
			'0900000000', '1990-01-01', 'active', TRUE
		)`,
		hash.DummyPasswordHash,
	); err != nil {
		t.Fatalf("insert changed bootstrap record: %v", err)
	}

	if err := migrator.Steps(1); err != nil {
		t.Fatalf("reapply migration 19: %v", err)
	}
	assertUserCount(t, db, bootstrapLookup, 1)

	if err := migrator.Steps(-1); err != nil {
		t.Fatalf("roll back irreversible migration 19: %v", err)
	}
	assertUserCount(t, db, bootstrapLookup, 1)
}

func assertUserCount(t *testing.T, db *sql.DB, lookup string, want int) {
	t.Helper()

	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM (%s) AS matched_user", lookup)
	if err := db.QueryRow(query).Scan(&count); err != nil {
		t.Fatalf("count bootstrap users: %v", err)
	}
	if count != want {
		t.Fatalf("bootstrap user count = %d, want %d", count, want)
	}
}

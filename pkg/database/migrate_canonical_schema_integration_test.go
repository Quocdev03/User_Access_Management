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

func TestCanonicalSchemaEmptyDatabaseMigration(t *testing.T) {
	db, migrator, databaseName := canonicalSchemaMigrator(t)

	if err := migrator.Migrate(30); err != nil {
		t.Fatalf("migrate empty database: %v", err)
	}
	assertCanonicalSchema(t, db, databaseName)
}

func TestCanonicalSchemaCurrentDataMigration(t *testing.T) {
	db, migrator, databaseName := canonicalSchemaMigrator(t)

	if err := migrator.Migrate(19); err != nil {
		t.Fatalf("migrate fixture database to version 19: %v", err)
	}
	insertCanonicalSchemaFixture(t, db)

	if err := migrator.Migrate(30); err != nil {
		t.Fatalf("migrate current-data fixture: %v", err)
	}
	assertCanonicalSchema(t, db, databaseName)
	assertCanonicalSchemaData(t, db)
}

func TestCanonicalSchemaDuplicatePermissionMigrationStops(t *testing.T) {
	db, migrator, _ := canonicalSchemaMigrator(t)

	if err := migrator.Migrate(19); err != nil {
		t.Fatalf("migrate duplicate fixture database to version 19: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO permissions (
			name, resource, action
		) VALUES
			('canonical_duplicate_a', 'canonical_resource', 'canonical_action'),
			('canonical_duplicate_b', 'canonical_resource', 'canonical_action')
	`); err != nil {
		t.Fatalf("insert duplicate permission fixture: %v", err)
	}

	if err := migrator.Up(); err == nil {
		t.Fatal("migration succeeded despite duplicate permission semantics")
	}

	var version uint
	var dirty bool
	if err := db.QueryRow(
		"SELECT version, dirty FROM schema_migrations LIMIT 1",
	).Scan(&version, &dirty); err != nil {
		t.Fatalf("read duplicate migration state: %v", err)
	}
	if version != 26 || !dirty {
		t.Fatalf("duplicate migration state = version %d dirty=%t, want version 26 dirty", version, dirty)
	}
	assertScalar(t, db,
		"SELECT COUNT(*) FROM permissions WHERE resource = 'canonical_resource' AND action = 'canonical_action'",
		2,
	)
}

func canonicalSchemaMigrator(t *testing.T) (*sql.DB, *migrate.Migrate, string) {
	t.Helper()

	cfg := mysqlDriver.Config{
		User:                 os.Getenv("UAM_MIGRATION_TEST_DB_USER"),
		Passwd:               os.Getenv("UAM_MIGRATION_TEST_DB_PASSWORD"),
		Net:                  "tcp",
		Addr:                 os.Getenv("UAM_MIGRATION_TEST_DB_ADDR"),
		DBName:               os.Getenv("UAM_CANONICAL_MIGRATION_DB_NAME"),
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
		t.Skip("canonical schema migration integration database is not configured")
	}
	if !strings.HasPrefix(cfg.DBName, "uam_canonical_migration_test_") {
		t.Fatalf("refusing non-disposable database %q", cfg.DBName)
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open canonical schema migration database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	driver, err := migrateMySQL.WithInstance(db, &migrateMySQL.Config{})
	if err != nil {
		t.Fatalf("create canonical schema migration driver: %v", err)
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
		t.Fatalf("create canonical schema migrator: %v", err)
	}
	t.Cleanup(func() {
		_, _ = migrator.Close()
	})

	return db, migrator, cfg.DBName
}

func insertCanonicalSchemaFixture(t *testing.T, db *sql.DB) {
	t.Helper()

	_, err := db.Exec(`
		INSERT INTO users (
			username, email, password_hash, full_name, phone, date_of_birth,
			status, email_verified, must_change_password, locked_until
		) VALUES
			('canonical_active', 'canonical_active@example.test', 'hash', 'Active User', '1', '1990-01-01', 'active', 1, 0, NULL),
			('canonical_pending', 'canonical_pending@example.test', 'hash', 'Pending User', '2', '1990-01-02', 'inactive', 0, 1, NULL),
			('canonical_disabled', 'canonical_disabled@example.test', 'hash', 'Disabled User', '3', '1990-01-03', 'inactive', 1, 0, NULL),
			('canonical_admin_locked', 'canonical_admin_locked@example.test', 'hash', 'Admin Locked', '4', '1990-01-04', 'locked', 1, 0, NULL),
			('canonical_login_locked', 'canonical_login_locked@example.test', 'hash', 'Login Locked', '5', '1990-01-05', 'locked', 1, 0, '2030-01-01 00:00:00')
	`)
	if err != nil {
		t.Fatalf("insert account-state fixtures: %v", err)
	}

	var activeID uint64
	if err := db.QueryRow(
		"SELECT id FROM users WHERE username = 'canonical_active'",
	).Scan(&activeID); err != nil {
		t.Fatalf("load active fixture id: %v", err)
	}
	var pendingID uint64
	if err := db.QueryRow(
		"SELECT id FROM users WHERE username = 'canonical_pending'",
	).Scan(&pendingID); err != nil {
		t.Fatalf("load pending fixture id: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO sessions (
			user_id, token_hash, refresh_token_hash, jti, expires_at
		) VALUES
			(?, 'canonical-token-no-jti', 'canonical-refresh-no-jti', NULL, '2030-01-01 00:00:00'),
			(?, 'canonical-token-valid', 'canonical-refresh-valid', 'canonical-valid-jti', '2030-01-01 00:00:00')
	`, activeID, activeID)
	if err != nil {
		t.Fatalf("insert session fixtures: %v", err)
	}

	if _, err := db.Exec(
		`INSERT INTO password_reset_tokens
			(user_id, token_hash, expires_at)
		 VALUES (?, 'canonical-reset-token', '2030-01-01 00:00:00')`,
		activeID,
	); err != nil {
		t.Fatalf("insert password-reset fixture: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO otp_codes (
			user_id, code, type, attempts, is_used, expires_at, created_at
		) VALUES (
			?, 'canonical-email-verification-hash', 'email_verification',
			2, FALSE, '2030-01-01 00:00:00', '2026-01-01 00:00:00'
		)`,
		pendingID,
	); err != nil {
		t.Fatalf("insert email-verification fixture: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO audit_logs
			(user_id, action, status)
		 VALUES (?, 'CANONICAL_SCHEMA_FIXTURE', 'success')`,
		activeID,
	); err != nil {
		t.Fatalf("insert audit fixture: %v", err)
	}
}

func assertCanonicalSchema(t *testing.T, db *sql.DB, databaseName string) {
	t.Helper()

	var version uint
	var dirty bool
	if err := db.QueryRow(
		"SELECT version, dirty FROM schema_migrations LIMIT 1",
	).Scan(&version, &dirty); err != nil {
		t.Fatalf("read final migration version: %v", err)
	}
	if version != 30 || dirty {
		t.Fatalf("schema state = version %d dirty=%t, want version 30 clean", version, dirty)
	}

	for _, table := range []string{
		"user_profiles",
		"refresh_token_history",
		"email_change_requests",
		"verification_challenges",
		"outbox_events",
	} {
		var count int
		if err := db.QueryRow(
			`SELECT COUNT(*)
			 FROM information_schema.tables
			 WHERE table_schema = ? AND table_name = ?`,
			databaseName,
			table,
		).Scan(&count); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("table %s count = %d, want 1", table, count)
		}
	}

	for _, column := range []struct {
		table string
		name  string
	}{
		{"users", "lifecycle_state"},
		{"users", "administrative_locked_at"},
		{"users", "login_locked_until"},
		{"users", "password_change_required"},
		{"users", "auth_version"},
		{"sessions", "access_jti"},
		{"sessions", "current_refresh_hash"},
		{"sessions", "revoked_at"},
		{"password_reset_tokens", "auth_version"},
		{"password_reset_tokens", "consumed_at"},
		{"roles", "is_system"},
	} {
		var count int
		if err := db.QueryRow(
			`SELECT COUNT(*)
			 FROM information_schema.columns
			 WHERE table_schema = ? AND table_name = ? AND column_name = ?`,
			databaseName,
			column.table,
			column.name,
		).Scan(&count); err != nil {
			t.Fatalf("check column %s.%s: %v", column.table, column.name, err)
		}
		if count != 1 {
			t.Errorf("column %s.%s count = %d, want 1", column.table, column.name, count)
		}
	}

	var permissionUnique int
	if err := db.QueryRow(
		`SELECT COUNT(*)
		 FROM information_schema.statistics
		 WHERE table_schema = ?
		   AND table_name = 'permissions'
		   AND index_name = 'uk_permissions_resource_action'
		   AND non_unique = 0`,
		databaseName,
	).Scan(&permissionUnique); err != nil {
		t.Fatalf("check permission unique index: %v", err)
	}
	if permissionUnique != 2 {
		t.Errorf("permission unique index columns = %d, want 2", permissionUnique)
	}

	var legacyClientIdentityUnique int
	if err := db.QueryRow(
		`SELECT COUNT(*)
		 FROM information_schema.statistics
		 WHERE table_schema = ?
		   AND table_name = 'devices'
		   AND index_name = 'uk_devices_user_os_browser'`,
		databaseName,
	).Scan(&legacyClientIdentityUnique); err != nil {
		t.Fatalf("check legacy client-profile unique index: %v", err)
	}
	if legacyClientIdentityUnique != 0 {
		t.Errorf(
			"legacy client-profile unique index columns = %d, want 0",
			legacyClientIdentityUnique,
		)
	}

	var auditDeleteRule string
	if err := db.QueryRow(
		`SELECT delete_rule
		 FROM information_schema.referential_constraints
		 WHERE constraint_schema = ?
		   AND table_name = 'audit_logs'
		   AND constraint_name = 'fk_audit_logs_user_id'`,
		databaseName,
	).Scan(&auditDeleteRule); err != nil {
		t.Fatalf("check audit foreign key: %v", err)
	}
	if auditDeleteRule != "SET NULL" {
		t.Errorf("audit delete rule = %q, want SET NULL", auditDeleteRule)
	}
}

func assertCanonicalSchemaData(t *testing.T, db *sql.DB) {
	t.Helper()

	expectedStates := map[string]string{
		"canonical_active":       "active",
		"canonical_pending":      "pending_verification",
		"canonical_disabled":     "disabled",
		"canonical_admin_locked": "active",
		"canonical_login_locked": "active",
	}
	for username, want := range expectedStates {
		var got string
		if err := db.QueryRow(
			"SELECT lifecycle_state FROM users WHERE username = ?",
			username,
		).Scan(&got); err != nil {
			t.Fatalf("load lifecycle for %s: %v", username, err)
		}
		if got != want {
			t.Errorf("lifecycle for %s = %q, want %q", username, got, want)
		}
	}

	assertScalar(t, db,
		"SELECT COUNT(*) FROM user_profiles WHERE full_name LIKE '%User' OR full_name LIKE '%Locked'",
		5,
	)
	assertScalar(t, db,
		"SELECT COUNT(*) FROM sessions WHERE token_hash = 'canonical-token-no-jti'",
		0,
	)
	assertScalar(t, db,
		`SELECT COUNT(*) FROM sessions
		 WHERE token_hash = 'canonical-token-valid'
		   AND access_jti = 'canonical-valid-jti'
		   AND current_refresh_hash = 'canonical-refresh-valid'`,
		1,
	)
	assertScalar(t, db,
		"SELECT COUNT(*) FROM users WHERE auth_version = 0",
		5,
	)
	assertScalar(t, db,
		"SELECT COUNT(*) FROM roles WHERE name IN ('admin', 'moderator', 'user') AND is_system = 1",
		3,
	)
	assertScalar(t, db,
		"SELECT COUNT(*) FROM audit_logs WHERE action = 'CANONICAL_SCHEMA_FIXTURE'",
		1,
	)
	assertScalar(t, db,
		`SELECT COUNT(*)
		 FROM verification_challenges
		 WHERE purpose = 'email_verification'
		   AND subject = 'canonical_pending@example.test'
		   AND secret_hash = 'canonical-email-verification-hash'
		   AND attempts = 2`,
		1,
	)
}

func assertScalar(t *testing.T, db *sql.DB, query string, want int) {
	t.Helper()

	var got int
	if err := db.QueryRow(query).Scan(&got); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	if got != want {
		t.Fatalf("query %q = %d, want %d", query, got, want)
	}
}

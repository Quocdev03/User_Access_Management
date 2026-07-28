//go:build integration

package account_test

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/access"
	accountapp "github.com/quocdev03/user-access-management/internal/account"
	"github.com/quocdev03/user-access-management/internal/blob"
	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/database"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

var (
	accountMigrationOnce sync.Once
	accountMigrationErr  error
)

func TestProfileGetAndUpdateUseCanonicalProjection(t *testing.T) {
	db := openAccountIntegrationDB(t)
	profile, userID := profileFixture(t, db, "canonical")

	got, err := profile.Get(context.Background(), userID)
	if err != nil {
		t.Fatalf("Get(): %v", err)
	}
	if got.ID != userID ||
		got.Username != "profile_integration_canonical" ||
		got.Email != "profile_integration_canonical@example.test" ||
		got.FullName != "Profile Integration canonical" ||
		got.Phone != "0907000000" ||
		got.DateOfBirth != "1991-07-01" ||
		got.Status != "active" ||
		len(got.Roles) != 1 ||
		got.Roles[0] != access.RoleUser {
		t.Fatalf("profile view = %+v", got)
	}

	fullName := "Profile Updated"
	dateOfBirth := "1992-08-02"
	if err := profile.Update(context.Background(), userID, accountapp.UpdateProfileCommand{
		FullName:    &fullName,
		DateOfBirth: &dateOfBirth,
		IPAddress:   "127.0.0.30",
		UserAgent:   "profile-integration-update",
	}); err != nil {
		t.Fatalf("Update(): %v", err)
	}

	var state struct {
		CanonicalName  string `db:"canonical_name"`
		CanonicalPhone string `db:"canonical_phone"`
		CanonicalDOB   string `db:"canonical_dob"`
		AuthVersion    uint64 `db:"auth_version"`
	}
	if err := db.Get(&state, `
		SELECT p.full_name AS canonical_name,
			p.phone AS canonical_phone,
			DATE_FORMAT(p.date_of_birth, '%Y-%m-%d') AS canonical_dob,
			u.auth_version
		FROM user_profiles p
		JOIN users u ON u.id = p.user_id
		WHERE p.user_id = ?`,
		userID,
	); err != nil {
		t.Fatalf("load updated profile: %v", err)
	}
	if state.CanonicalName != fullName ||
		state.CanonicalPhone != "0907000000" ||
		state.CanonicalDOB != dateOfBirth ||
		state.AuthVersion != 1 {
		t.Fatalf("updated profile state = %+v", state)
	}
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE user_id = ?
		  AND action = 'UPDATE_PROFILE'
		  AND status = 'success'`,
		userID,
		1,
	)
}

func TestConcurrentProfileUpdatesDoNotLoseDifferentFields(t *testing.T) {
	db := openAccountIntegrationDB(t)
	profile, userID := profileFixture(t, db, "concurrent")
	fullName := "Concurrent Name"
	phone := "0907999999"

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- profile.Update(context.Background(), userID, accountapp.UpdateProfileCommand{
			FullName: &fullName,
		})
	}()
	go func() {
		<-start
		results <- profile.Update(context.Background(), userID, accountapp.UpdateProfileCommand{
			Phone: &phone,
		})
	}()
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent Update(): %v", err)
		}
	}

	var canonical struct {
		FullName string `db:"full_name"`
		Phone    string `db:"phone"`
	}
	if err := db.Get(
		&canonical,
		"SELECT full_name, phone FROM user_profiles WHERE user_id = ?",
		userID,
	); err != nil {
		t.Fatalf("load concurrent profile: %v", err)
	}
	if canonical.FullName != fullName || canonical.Phone != phone {
		t.Fatalf("concurrent profile = %+v", canonical)
	}
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE user_id = ? AND action = 'UPDATE_PROFILE'`,
		userID,
		2,
	)
}

func profileFixture(
	t *testing.T,
	db *sqlx.DB,
	suffix string,
) (*accountapp.Profile, uint64) {
	t.Helper()
	username := "profile_integration_" + suffix
	email := username + "@example.test"
	result, err := db.Exec(`
		INSERT INTO users (
			username, email, password_hash, lifecycle_state, email_verified,
			administrative_locked_at, login_locked_until,
			failed_login_attempts, password_change_required, auth_version
		) VALUES (?, ?, ?, 'active', TRUE, NULL, NULL, 0, FALSE, 1)`,
		username,
		email,
		hash.DummyPasswordHash,
	)
	if err != nil {
		t.Fatalf("create profile account: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read profile account ID: %v", err)
	}
	userID := uint64(id)
	if _, err := db.Exec(`
		INSERT INTO user_profiles (
			user_id, full_name, phone, date_of_birth
		) VALUES (?, ?, ?, ?)`,
		userID,
		"Profile Integration "+suffix,
		"0907000000",
		"1991-07-01",
	); err != nil {
		t.Fatalf("create canonical profile: %v", err)
	}
	roles := mysqlstore.NewRoleStore(db)
	if err := roles.AssignRoleByName(context.Background(), userID, access.RoleUser); err != nil {
		t.Fatalf("assign user role: %v", err)
	}
	blobStore, err := blob.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore(): %v", err)
	}
	return accountapp.NewProfile(
		db,
		mysqlstore.NewAccountStore(db),
		mysqlstore.NewProfileStore(db),
		roles,
		mysqlstore.NewAuditStore(db),
		blobStore,
	), userID
}

func openAccountIntegrationDB(t *testing.T) *sqlx.DB {
	t.Helper()
	name := os.Getenv("UAM_ACCOUNT_TEST_DB_NAME")
	if !strings.HasPrefix(name, "uam_account_test_") {
		t.Skip("disposable account database is not configured")
	}
	address := os.Getenv("UAM_ACCOUNT_TEST_DB_ADDR")
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("parse account integration database address: %v", err)
	}
	user := os.Getenv("UAM_ACCOUNT_TEST_DB_USER")
	password := os.Getenv("UAM_ACCOUNT_TEST_DB_PASSWORD")
	accountMigrationOnce.Do(func() {
		accountMigrationErr = database.RunMigrations(config.DatabaseConfig{
			Host:     host,
			Port:     port,
			Name:     name,
			User:     user,
			Password: password,
		}, "../../migrations", "test")
	})
	if accountMigrationErr != nil {
		t.Fatalf("run account integration migrations: %v", accountMigrationErr)
	}
	cfg := mysql.Config{
		User:                 user,
		Passwd:               password,
		Net:                  "tcp",
		Addr:                 address,
		DBName:               name,
		ParseTime:            true,
		Loc:                  time.UTC,
		AllowNativePasswords: true,
	}
	db, err := sqlx.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open account integration database: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("ping account integration database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func assertAccountScalar(
	t *testing.T,
	db *sqlx.DB,
	query string,
	args ...any,
) {
	t.Helper()
	want := args[len(args)-1].(int)
	var got int
	if err := db.Get(&got, query, args[:len(args)-1]...); err != nil {
		t.Fatalf("query account scalar: %v", err)
	}
	if got != want {
		t.Fatalf("account scalar = %d, want %d", got, want)
	}
}

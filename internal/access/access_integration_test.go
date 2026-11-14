//go:build integration

package access

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/accountstate"
	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/database"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

// File này kiểm chứng tích hợp access integration với các dependency runtime liên quan.

// TestAccessSecurityIntegration kiểm chứng kịch bản AccessSecurityIntegration.
func TestAccessSecurityIntegration(t *testing.T) {
	db := openAccessIntegrationDB(t)

	t.Run("custom permission authorizes without moderator role", func(t *testing.T) {
		resetAccessFixtures(t, db)
		actorID := createAccessUser(t, db, "custom_permission_actor")
		store := mysqlstore.NewAccessStore(db)
		roleID, err := store.CreateRole(
			context.Background(),
			"access_reader",
			"access custom reader",
		)
		if err != nil {
			t.Fatalf("create custom role: %v", err)
		}
		var permissionID uint64
		if err := db.Get(
			&permissionID,
			`SELECT id FROM permissions WHERE name = 'users.read'`,
		); err != nil {
			t.Fatalf("find users.read permission: %v", err)
		}
		if err := store.ReplaceRolePermissions(
			context.Background(),
			roleID,
			[]uint64{permissionID},
		); err != nil {
			t.Fatalf("assign custom permission: %v", err)
		}
		if err := store.AssignRole(context.Background(), actorID, roleID); err != nil {
			t.Fatalf("assign custom role: %v", err)
		}

		allowed, err := NewAuthorizer(store).Allowed(
			context.Background(),
			actorID,
			"users.read",
		)
		if err != nil {
			t.Fatalf("authorize custom permission: %v", err)
		}
		if !allowed {
			t.Fatal("custom permission was blocked by a hard-coded role gate")
		}
		roles, err := store.RoleNamesByUserID(context.Background(), actorID)
		if err != nil {
			t.Fatalf("read actor roles: %v", err)
		}
		if containsRoleName(roles, "admin") || containsRoleName(roles, "moderator") {
			t.Fatalf("custom-permission actor received privileged role: %v", roles)
		}
	})

	t.Run("moderator cannot mutate admin target", func(t *testing.T) {
		resetAccessFixtures(t, db)
		adminID := createAccessUser(t, db, "guard_admin")
		moderatorID := createAccessUser(t, db, "guard_moderator")
		assignSystemRole(t, db, adminID, "admin")
		assignSystemRole(t, db, moderatorID, "moderator")
		users := newAccessUsers(t, db)
		newName := "Unauthorized Update"

		err := users.Update(context.Background(), UpdateUserCommand{
			ActorID:  moderatorID,
			TargetID: adminID,
			FullName: &newName,
		})
		assertAccessErrorCode(t, err, apperror.ErrForbidden.Code)

		var fullName string
		if err := db.Get(
			&fullName,
			`SELECT full_name FROM user_profiles WHERE user_id = ?`,
			adminID,
		); err != nil {
			t.Fatalf("read guarded admin profile: %v", err)
		}
		if fullName == newName {
			t.Fatal("moderator mutation reached the admin target")
		}
	})

	t.Run("concurrent mutations preserve one usable admin", func(t *testing.T) {
		resetAccessFixtures(t, db)
		firstID := createAccessUser(t, db, "last_admin_first")
		secondID := createAccessUser(t, db, "last_admin_second")
		assignSystemRole(t, db, firstID, "admin")
		assignSystemRole(t, db, secondID, "admin")
		users := newAccessUsers(t, db)

		start := make(chan struct{})
		results := make(chan error, 2)
		var wait sync.WaitGroup
		for _, command := range []ChangeStatusCommand{
			{ActorID: firstID, TargetID: secondID, Status: "inactive"},
			{ActorID: secondID, TargetID: firstID, Status: "inactive"},
		} {
			command := command
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				results <- users.ChangeStatus(context.Background(), command)
			}()
		}
		close(start)
		wait.Wait()
		close(results)

		successes := 0
		rejections := 0
		for err := range results {
			switch {
			case err == nil:
				successes++
			case accessErrorCode(err) == apperror.ErrBadRequest.Code:
				rejections++
			default:
				t.Fatalf("unexpected concurrent last-admin result: %v", err)
			}
		}
		if successes != 1 || rejections != 1 {
			t.Fatalf(
				"concurrent last-admin results: successes=%d rejections=%d",
				successes,
				rejections,
			)
		}
		var usable int
		if err := db.Get(&usable, `
			SELECT COUNT(*)
			FROM users u
			INNER JOIN user_roles ur ON ur.user_id = u.id
			INNER JOIN roles r ON r.id = ur.role_id
			WHERE r.name = 'admin'
			  AND r.is_system = TRUE
			  AND u.lifecycle_state = 'active'
			  AND u.email_verified = TRUE
			  AND u.administrative_locked_at IS NULL`); err != nil {
			t.Fatalf("count usable admins: %v", err)
		}
		if usable != 1 {
			t.Fatalf("usable admins = %d, want 1", usable)
		}
	})

	t.Run("admin reset issues durable one-time link", func(t *testing.T) {
		resetAccessFixtures(t, db)
		adminID := createAccessUser(t, db, "reset_admin")
		targetID := createAccessUser(t, db, "reset_target")
		assignSystemRole(t, db, adminID, "admin")
		insertAccessSession(t, db, targetID)
		users := newAccessUsers(t, db)

		var oldHash string
		if err := db.Get(
			&oldHash,
			`SELECT password_hash FROM users WHERE id = ?`,
			targetID,
		); err != nil {
			t.Fatalf("read original password hash: %v", err)
		}
		if err := users.RequestPasswordReset(
			context.Background(),
			ResetPasswordCommand{ActorID: adminID, TargetID: targetID},
		); err != nil {
			t.Fatalf("request admin password reset: %v", err)
		}

		var state struct {
			PasswordHash string `db:"password_hash"`
			AuthVersion  uint64 `db:"auth_version"`
			Sessions     int    `db:"sessions"`
			ResetTokens  int    `db:"reset_tokens"`
			Deliveries   int    `db:"deliveries"`
		}
		if err := db.Get(&state, `
			SELECT u.password_hash, u.auth_version,
				(SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) AS sessions,
				(SELECT COUNT(*) FROM password_reset_tokens pr
					WHERE pr.user_id = u.id AND pr.consumed_at IS NULL
						AND pr.auth_version = u.auth_version) AS reset_tokens,
				(SELECT COUNT(*) FROM outbox_events o
					WHERE o.event_type = 'mail.password_reset_requested'
						AND o.delivered_at IS NULL
						AND o.dead_lettered_at IS NULL) AS deliveries
			FROM users u
			WHERE u.id = ?`,
			targetID,
		); err != nil {
			t.Fatalf("read admin reset result: %v", err)
		}
		if state.PasswordHash != oldHash {
			t.Fatal("admin reset replaced the password with a temporary credential")
		}
		if state.AuthVersion != 1 ||
			state.Sessions != 0 ||
			state.ResetTokens != 1 ||
			state.Deliveries != 1 {
			t.Fatalf("admin reset state = %+v", state)
		}
	})

	t.Run("empty permission list clears role and invalidates assignees", func(t *testing.T) {
		resetAccessFixtures(t, db)
		adminID := createAccessUser(t, db, "permissions_admin")
		targetID := createAccessUser(t, db, "permissions_target")
		assignSystemRole(t, db, adminID, "admin")
		store := mysqlstore.NewAccessStore(db)
		roleID, err := store.CreateRole(
			context.Background(),
			"access_permission_clear",
			"access permission clear",
		)
		if err != nil {
			t.Fatalf("create permission-clear role: %v", err)
		}
		var permissionID uint64
		if err := db.Get(
			&permissionID,
			`SELECT id FROM permissions WHERE name = 'users.read'`,
		); err != nil {
			t.Fatalf("find users.read permission: %v", err)
		}
		if err := store.ReplaceRolePermissions(
			context.Background(),
			roleID,
			[]uint64{permissionID},
		); err != nil {
			t.Fatalf("seed role permission: %v", err)
		}
		if err := store.AssignRole(context.Background(), targetID, roleID); err != nil {
			t.Fatalf("assign permission-clear role: %v", err)
		}
		insertAccessSession(t, db, targetID)

		roles := NewRoles(
			db,
			store,
			mysqlstore.NewAccountStore(db),
			mysqlstore.NewAuditStore(db),
			mysqlstore.NewAuthInvalidator(db),
		)
		if err := roles.ReplacePermissions(
			context.Background(),
			ReplacePermissionsCommand{
				ActorID:       adminID,
				RoleID:        roleID,
				PermissionIDs: []uint64{},
			},
		); err != nil {
			t.Fatalf("clear role permissions: %v", err)
		}
		var result struct {
			Permissions int    `db:"permissions"`
			AuthVersion uint64 `db:"auth_version"`
			Sessions    int    `db:"sessions"`
		}
		if err := db.Get(&result, `
			SELECT
				(SELECT COUNT(*) FROM role_permissions WHERE role_id = ?) AS permissions,
				u.auth_version,
				(SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) AS sessions
			FROM users u
			WHERE u.id = ?`,
			roleID,
			targetID,
		); err != nil {
			t.Fatalf("read permission-clear result: %v", err)
		}
		if result.Permissions != 0 || result.AuthVersion != 1 || result.Sessions != 0 {
			t.Fatalf("permission-clear result = %+v", result)
		}
	})
}

// accessTestBlob là stub implementation của blob store phục vụ access integration test.
type accessTestBlob struct{}

// Put ghi put trong access use case.
func (accessTestBlob) Put(context.Context, string, io.Reader) error { return nil }

// Delete mô phỏng blob deletion cho integration fixture của access use case.
func (accessTestBlob) Delete(context.Context, string) error { return nil }

// URL tạo fake public URL cho blob fixture của access test.
func (accessTestBlob) URL(key string) string { return key }

// newAccessUsers wire use case quản trị người dùng với store integration fixture.
func newAccessUsers(t *testing.T, db *sqlx.DB) *Users {
	t.Helper()
	codec, err := mail.NewSecretCodec("access-integration-pepper")
	if err != nil {
		t.Fatalf("create access payload codec: %v", err)
	}
	return NewUsers(
		db,
		mysqlstore.NewAccessStore(db),
		mysqlstore.NewAccountStore(db),
		mysqlstore.NewProfileStore(db),
		mysqlstore.NewEmailChangeStore(db),
		mysqlstore.NewPasswordResetStore(db),
		mysqlstore.NewOutboxStore(db),
		mysqlstore.NewAuditStore(db),
		mysqlstore.NewAuthInvalidator(db),
		codec,
		accessTestBlob{},
		time.Hour,
	)
}

// createAccessUser tạo access người dùng trong access use case.
func createAccessUser(t *testing.T, db *sqlx.DB, suffix string) uint64 {
	t.Helper()
	now := time.Now().UTC()
	accounts := mysqlstore.NewAccountStore(db)
	account := &mysqlstore.RegistrationAccount{
		Username:     "access_" + suffix,
		Email:        "access_" + suffix + "@example.test",
		PasswordHash: hash.DummyPasswordHash,
	}
	if err := accounts.CreateRegistration(context.Background(), account, now); err != nil {
		t.Fatalf("create access user: %v", err)
	}
	if err := mysqlstore.NewProfileStore(db).Upsert(
		context.Background(),
		&mysqlstore.Profile{
			UserID:      account.ID,
			FullName:    "Access Integration User",
			Phone:       "0900000000",
			DateOfBirth: time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	); err != nil {
		t.Fatalf("create access profile: %v", err)
	}
	if err := accounts.UpdateState(
		context.Background(),
		account.ID,
		accountstate.State{
			Lifecycle:     accountstate.Active,
			EmailVerified: true,
		},
		now,
	); err != nil {
		t.Fatalf("activate access user: %v", err)
	}
	return account.ID
}

// assignSystemRole gán system role trong access use case.
func assignSystemRole(t *testing.T, db *sqlx.DB, userID uint64, roleName string) {
	t.Helper()
	store := mysqlstore.NewAccessStore(db)
	role, err := store.FindRoleByName(context.Background(), roleName)
	if err != nil || role == nil {
		t.Fatalf("find system role %q: role=%v error=%v", roleName, role, err)
	}
	if err := store.AssignRole(context.Background(), userID, role.ID); err != nil {
		t.Fatalf("assign system role %q: %v", roleName, err)
	}
}

// insertAccessSession tạo session để kiểm chứng hệ quả invalidation của admin mutation.
func insertAccessSession(t *testing.T, db *sqlx.DB, userID uint64) {
	t.Helper()
	jti := "access-integration-jti"
	if err := mysqlstore.NewSessionStore(db).Create(context.Background(), &mysqlstore.Session{
		UserID:             userID,
		CurrentRefreshHash: "access-integration-refresh",
		AccessJTI:          jti,
		ExpiresAt:          time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create access session: %v", err)
	}
}

// resetAccessFixtures xóa dữ liệu RBAC theo thứ tự foreign-key an toàn giữa các test.
func resetAccessFixtures(t *testing.T, db *sqlx.DB) {
	t.Helper()
	for _, query := range []string{
		`DELETE FROM outbox_events`,
		`DELETE FROM verification_challenges`,
		`DELETE FROM email_change_requests`,
		`DELETE FROM password_reset_tokens`,
		`DELETE FROM refresh_token_history`,
		`DELETE FROM sessions`,
		`DELETE FROM devices`,
		`DELETE FROM audit_logs`,
		`DELETE FROM user_roles`,
		`DELETE FROM user_profiles`,
		`DELETE FROM users`,
		`DELETE rp FROM role_permissions rp
			INNER JOIN roles r ON r.id = rp.role_id
			WHERE r.is_system = FALSE`,
		`DELETE FROM roles WHERE is_system = FALSE`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatalf("reset access fixture with %q: %v", query, err)
		}
	}
}

// openAccessIntegrationDB kết nối disposable MySQL cho access integration test.
func openAccessIntegrationDB(t *testing.T) *sqlx.DB {
	t.Helper()
	dbConfig := config.DatabaseConfig{
		Host:     os.Getenv("UAM_ACCESS_TEST_DB_HOST"),
		Port:     os.Getenv("UAM_ACCESS_TEST_DB_PORT"),
		Name:     os.Getenv("UAM_ACCESS_TEST_DB_NAME"),
		User:     os.Getenv("UAM_ACCESS_TEST_DB_USER"),
		Password: os.Getenv("UAM_ACCESS_TEST_DB_PASSWORD"),
	}
	if dbConfig.Host == "" {
		dbConfig.Host = "127.0.0.1"
	}
	if dbConfig.Port == "" {
		dbConfig.Port = "3306"
	}
	if dbConfig.User == "" || dbConfig.Name == "" {
		t.Skip("access integration database is not configured")
	}
	if !strings.HasPrefix(dbConfig.Name, "uam_access_test_") {
		t.Fatalf("refusing non-disposable database %q", dbConfig.Name)
	}
	if err := database.RunMigrations(dbConfig.MySQLOptions(), "../../migrations", "test"); err != nil {
		t.Fatalf("run access migrations: %v", err)
	}
	db, err := database.ConnectMySQL(dbConfig.MySQLOptions())
	if err != nil {
		t.Fatalf("connect access database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// assertAccessErrorCode yêu cầu lỗi trả đúng public business code.
func assertAccessErrorCode(t *testing.T, err error, want string) {
	t.Helper()
	if got := accessErrorCode(err); got != want {
		t.Fatalf("error code = %q, want %q: %v", got, want, err)
	}
}

// accessErrorCode lấy business code từ error chain của access use case.
func accessErrorCode(err error) string {
	var appError *apperror.AppError
	if errors.As(err, &appError) {
		return appError.Code
	}
	return ""
}

// containsRoleName kiểm tra role projection có chứa tên mong đợi.
func containsRoleName(roles []string, name string) bool {
	for _, role := range roles {
		if role == name {
			return true
		}
	}
	return false
}

//go:build integration

package mysqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/accountstate"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	sessionapp "github.com/quocdev03/user-access-management/internal/session"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

func TestAccountStateTransactionCommitAndRollback(t *testing.T) {
	db := openIntegrationDB(t)
	userID := insertAccountFixture(t, db, "transaction")
	insertSessionFixture(t, db, userID, "transaction")

	txManager := mysqlstore.NewTxManager(db)
	accountStore := mysqlstore.NewAccountStore(db)
	invalidator := mysqlstore.NewAuthInvalidator(db)
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	rollbackMarker := errors.New("rollback marker")

	err := txManager.RunInTx(context.Background(), func(txCtx context.Context) error {
		account, err := accountStore.FindByIDForUpdate(txCtx, userID)
		if err != nil {
			return err
		}
		state, err := account.State()
		if err != nil {
			return err
		}
		state.Disable()
		if err := accountStore.UpdateState(txCtx, userID, state, now); err != nil {
			return err
		}
		if err := invalidator.Invalidate(txCtx, userID); err != nil {
			return err
		}
		return rollbackMarker
	})
	if !errors.Is(err, rollbackMarker) {
		t.Fatalf("rollback transaction error = %v, want marker", err)
	}
	assertAccountState(t, db, userID, "active", 0, 1)

	if err := txManager.RunInTx(context.Background(), func(txCtx context.Context) error {
		account, err := accountStore.FindByIDForUpdate(txCtx, userID)
		if err != nil {
			return err
		}
		state, err := account.State()
		if err != nil {
			return err
		}
		state.Disable()
		if err := accountStore.UpdateState(txCtx, userID, state, now); err != nil {
			return err
		}
		return invalidator.Invalidate(txCtx, userID)
	}); err != nil {
		t.Fatalf("commit account transition: %v", err)
	}
	assertAccountState(t, db, userID, "disabled", 2, 0)
}

func TestNestedTransactionIsRejected(t *testing.T) {
	db := openIntegrationDB(t)
	txManager := mysqlstore.NewTxManager(db)
	err := txManager.RunInTx(context.Background(), func(txCtx context.Context) error {
		return txManager.RunInTx(txCtx, func(context.Context) error {
			t.Fatal("nested transaction callback must not run")
			return nil
		})
	})
	if err == nil || !strings.Contains(err.Error(), "nested MySQL transaction") {
		t.Fatalf("nested transaction error = %v", err)
	}
}

func TestTargetStoresUseExpandedSchema(t *testing.T) {
	db := openIntegrationDB(t)
	ctx := context.Background()
	dateOfBirth := time.Date(1991, 2, 3, 0, 0, 0, 0, time.UTC)
	account := &mysqlstore.RegistrationAccount{
		Username:     "target_store",
		Email:        "target_store@example.test",
		PasswordHash: "hash",
	}

	accountStore := mysqlstore.NewAccountStore(db)
	if err := accountStore.CreateRegistration(ctx, account, time.Now().UTC()); err != nil {
		t.Fatalf("create user through account store: %v", err)
	}
	if err := mysqlstore.NewProfileStore(db).Upsert(ctx, &mysqlstore.Profile{
		UserID:      account.ID,
		FullName:    "Target Store",
		Phone:       "3",
		DateOfBirth: dateOfBirth,
	}); err != nil {
		t.Fatalf("create profile through profile store: %v", err)
	}
	loadedUser, err := accountStore.FindByID(ctx, account.ID)
	if err != nil {
		t.Fatalf("read user through account store: %v", err)
	}
	if loadedUser == nil || loadedUser.Username != account.Username {
		t.Fatalf("target user read = %+v, want username %q", loadedUser, account.Username)
	}

	var accountProjection struct {
		Lifecycle accountstate.Lifecycle `db:"lifecycle_state"`
		Profiles  int                    `db:"profiles"`
	}
	if err := db.Get(&accountProjection, `
		SELECT u.lifecycle_state,
			(SELECT COUNT(*) FROM user_profiles p WHERE p.user_id = u.id) AS profiles
		FROM users u
		WHERE u.id = ?`,
		account.ID,
	); err != nil {
		t.Fatalf("read canonical account projection: %v", err)
	}
	if accountProjection.Lifecycle != accountstate.PendingVerification ||
		accountProjection.Profiles != 1 {
		t.Fatalf("canonical account projection = %+v", accountProjection)
	}

	jti := "target_store_jti"
	session := &mysqlstore.Session{
		UserID:             account.ID,
		CurrentRefreshHash: "target_store_refresh",
		AccessJTI:          jti,
		ExpiresAt:          time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	sessionStore := mysqlstore.NewSessionStore(db)
	if err := sessionStore.Create(ctx, session); err != nil {
		t.Fatalf("create session through canonical store: %v", err)
	}
	sessions, err := sessionStore.FindActiveByUserID(ctx, account.ID)
	if err != nil {
		t.Fatalf("read sessions through canonical store: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != session.ID {
		t.Fatalf("target session read = %+v, want session %d", sessions, session.ID)
	}

	var sessionProjection struct {
		CurrentRefreshHash string `db:"current_refresh_hash"`
		AccessJTI          string `db:"access_jti"`
	}
	if err := db.Get(&sessionProjection, `
		SELECT current_refresh_hash, access_jti
		FROM sessions
		WHERE id = ?`,
		session.ID,
	); err != nil {
		t.Fatalf("read canonical session projection: %v", err)
	}
	if sessionProjection.CurrentRefreshHash != session.CurrentRefreshHash ||
		sessionProjection.AccessJTI != jti {
		t.Fatalf("canonical session projection = %+v", sessionProjection)
	}

	accessStore := mysqlstore.NewAccessStore(db)
	roles, err := accessStore.ListRoles(ctx)
	if err != nil {
		t.Fatalf("read roles through access store: %v", err)
	}
	if len(roles) == 0 {
		t.Fatal("access role read returned no seeded roles")
	}
	if _, err := accessStore.PermissionsByRoleIDs(ctx, []uint64{roles[0].ID}); err != nil {
		t.Fatalf("read role permissions through access store: %v", err)
	}

	auditStore := mysqlstore.NewAuditStore(db)
	auditLog := &mysqlstore.AuditLog{
		UserID: &account.ID,
		Action: "store.compatibility",
		Status: "success",
	}
	if err := auditStore.Create(ctx, auditLog); err != nil {
		t.Fatalf("create audit log through audit store: %v", err)
	}
	logs, err := auditStore.FindAllWithFilters(ctx, &account.ID, nil, nil, nil)
	if err != nil {
		t.Fatalf("read audit logs through audit store: %v", err)
	}
	if len(logs) != 1 || logs[0].ID != auditLog.ID {
		t.Fatalf("audit read = %+v, want audit %d", logs, auditLog.ID)
	}
}

func TestConcurrentRefreshRotationHasOneWinnerAndDurableReuse(t *testing.T) {
	db := openIntegrationDB(t)
	userID := insertAccountFixture(t, db, "refresh_race")
	initialJTI := "store_refresh_race_jti"
	initial := &mysqlstore.Session{
		UserID:             userID,
		CurrentRefreshHash: "store_refresh_race_refresh",
		AccessJTI:          initialJTI,
		ExpiresAt:          time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	store := mysqlstore.NewSessionStore(db)
	if err := store.Create(context.Background(), initial); err != nil {
		t.Fatalf("create refresh-race session: %v", err)
	}

	txManager := mysqlstore.NewTxManager(db)
	start := make(chan struct{})
	results := make(chan error, 2)
	for worker := 1; worker <= 2; worker++ {
		worker := worker
		go func() {
			<-start
			results <- txManager.RunInTx(context.Background(), func(txCtx context.Context) error {
				current, err := store.FindByCurrentRefreshHashForUpdate(
					txCtx,
					initial.CurrentRefreshHash,
				)
				if err != nil {
					return err
				}
				if current == nil {
					reused, err := store.RefreshHistoryExists(txCtx, initial.CurrentRefreshHash)
					if err != nil {
						return err
					}
					if reused {
						return apperror.ErrTokenReuse
					}
					return apperror.ErrSessionExpired
				}
				nextJTI := fmt.Sprintf("store_refresh_race_jti_%d", worker)
				current.CurrentRefreshHash = fmt.Sprintf("store_refresh_race_refresh_%d", worker)
				current.AccessJTI = nextJTI
				return store.Rotate(
					txCtx,
					current,
					initial.CurrentRefreshHash,
					initial.ExpiresAt,
				)
			})
		}()
	}
	close(start)

	var successes, reuseDetections int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, apperror.ErrTokenReuse):
			reuseDetections++
		default:
			t.Fatalf("concurrent refresh result: %v", err)
		}
	}
	if successes != 1 || reuseDetections != 1 {
		t.Fatalf("refresh results: successes=%d reuse=%d", successes, reuseDetections)
	}

	var history int
	if err := db.Get(&history,
		"SELECT COUNT(*) FROM refresh_token_history WHERE token_hash = ?",
		initial.CurrentRefreshHash,
	); err != nil {
		t.Fatalf("count durable refresh history: %v", err)
	}
	if history != 1 {
		t.Fatalf("refresh history rows = %d, want 1", history)
	}
}

func TestExpiredRefreshRevocationCommitsBeforeBusinessError(t *testing.T) {
	db := openIntegrationDB(t)
	userID := insertAccountFixture(t, db, "expired_refresh")
	jti := "store_expired_refresh_jti"
	expired := &mysqlstore.Session{
		UserID:             userID,
		CurrentRefreshHash: "store_expired_refresh_token",
		AccessJTI:          jti,
		ExpiresAt:          time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	store := mysqlstore.NewSessionStore(db)
	if err := store.Create(context.Background(), expired); err != nil {
		t.Fatalf("create expired session: %v", err)
	}

	tokenState := &fakeTokenState{}
	rotator := sessionapp.NewRotator(
		db,
		store,
		tokenState,
		sessionapp.NewInvalidator(db),
		15*time.Minute,
		24*time.Hour,
	)
	_, err := rotator.Rotate(
		context.Background(),
		sessionapp.RotationRequest{
			UserID:             userID,
			CurrentRefreshHash: expired.CurrentRefreshHash,
			RefreshExpiresAt:   expired.ExpiresAt,
		},
		func(context.Context) (sessionapp.RotationTokens, error) {
			t.Fatal("expired refresh must not authorize token issuance")
			return sessionapp.RotationTokens{}, nil
		},
	)
	if !errors.Is(err, apperror.ErrRefreshTokenInvalid) {
		t.Fatalf("rotate expired session error = %v, want refresh invalid", err)
	}

	var revokedAt sql.NullTime
	if err := db.Get(&revokedAt, "SELECT revoked_at FROM sessions WHERE id = ?", expired.ID); err != nil {
		t.Fatalf("read expired session revocation: %v", err)
	}
	if !revokedAt.Valid {
		t.Fatal("expired session revocation rolled back with its business error")
	}
}

func TestSingleSessionBlacklistFailureInvalidatesAllAuth(t *testing.T) {
	db := openIntegrationDB(t)
	userID := insertAccountFixture(t, db, "revoke_failure")
	jti := "store_revoke_failure_jti"
	active := &mysqlstore.Session{
		UserID:             userID,
		CurrentRefreshHash: "store_revoke_failure_refresh",
		AccessJTI:          jti,
		ExpiresAt:          time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	store := mysqlstore.NewSessionStore(db)
	if err := store.Create(context.Background(), active); err != nil {
		t.Fatalf("create revoke-failure session: %v", err)
	}

	tokenState := &fakeTokenState{blacklistErr: errors.New("redis unavailable")}
	manager := sessionapp.NewManager(
		db,
		store,
		mysqlstore.NewClientProfileStore(db),
		tokenState,
		sessionapp.NewInvalidator(db),
		15*time.Minute,
	)
	if err := manager.Revoke(context.Background(), userID, active.ID); err == nil {
		t.Fatal("single-session revoke succeeded despite blacklist failure")
	}

	var authVersion uint64
	if err := db.Get(&authVersion, "SELECT auth_version FROM users WHERE id = ?", userID); err != nil {
		t.Fatalf("read auth version: %v", err)
	}
	if authVersion != 1 {
		t.Fatalf("auth version = %d, want 1 after fail-closed compensation", authVersion)
	}
	var sessions int
	if err := db.Get(&sessions, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", userID); err != nil {
		t.Fatalf("count sessions after compensation: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("sessions = %d, want 0 after fail-closed compensation", sessions)
	}
}

func TestConcurrentRefreshAndSingleRevokeLeavesNoUsableSession(t *testing.T) {
	db := openIntegrationDB(t)
	userID := insertAccountFixture(t, db, "refresh_revoke")
	oldJTI := "store_refresh_revoke_old_jti"
	active := &mysqlstore.Session{
		UserID:             userID,
		CurrentRefreshHash: "store_refresh_revoke_old_refresh",
		AccessJTI:          oldJTI,
		ExpiresAt:          time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	store := mysqlstore.NewSessionStore(db)
	if err := store.Create(context.Background(), active); err != nil {
		t.Fatalf("create refresh-revoke session: %v", err)
	}

	tokenState := &fakeTokenState{}
	invalidator := sessionapp.NewInvalidator(db)
	rotator := sessionapp.NewRotator(
		db,
		store,
		tokenState,
		invalidator,
		15*time.Minute,
		24*time.Hour,
	)
	manager := sessionapp.NewManager(
		db,
		store,
		mysqlstore.NewClientProfileStore(db),
		tokenState,
		invalidator,
		15*time.Minute,
	)

	start := make(chan struct{})
	rotationResult := make(chan error, 1)
	revokeResult := make(chan error, 1)
	go func() {
		<-start
		_, err := rotator.Rotate(
			context.Background(),
			sessionapp.RotationRequest{
				UserID:             userID,
				CurrentRefreshHash: active.CurrentRefreshHash,
				RefreshExpiresAt:   active.ExpiresAt,
			},
			func(context.Context) (sessionapp.RotationTokens, error) {
				return sessionapp.RotationTokens{
					AccessToken:  "store_refresh_revoke_new_access",
					RefreshToken: "store_refresh_revoke_new_refresh",
					AccessJTI:    "store_refresh_revoke_new_jti",
				}, nil
			},
		)
		rotationResult <- err
	}()
	go func() {
		<-start
		revokeResult <- manager.Revoke(context.Background(), userID, active.ID)
	}()
	close(start)

	rotationErr := <-rotationResult
	revokeErr := <-revokeResult
	if revokeErr != nil {
		t.Fatalf("single-session revoke lost refresh race: %v", revokeErr)
	}
	if rotationErr != nil && !errors.Is(rotationErr, apperror.ErrSessionExpired) {
		t.Fatalf("refresh race error = %v, want success or session expired", rotationErr)
	}

	var activeSessions int
	if err := db.Get(&activeSessions, `
		SELECT COUNT(*)
		FROM sessions
		WHERE id = ? AND revoked_at IS NULL`,
		active.ID,
	); err != nil {
		t.Fatalf("count active refresh-revoke session: %v", err)
	}
	if activeSessions != 0 {
		t.Fatalf("active refresh-revoke sessions = %d, want 0", activeSessions)
	}
}

func TestConcurrentRefreshAndLogoutHasOneConsistentWinner(t *testing.T) {
	db := openIntegrationDB(t)
	userID := insertAccountFixture(t, db, "refresh_logout")
	oldJTI := "store_refresh_logout_old_jti"
	active := &mysqlstore.Session{
		UserID:             userID,
		CurrentRefreshHash: "store_refresh_logout_old_refresh",
		AccessJTI:          oldJTI,
		ExpiresAt:          time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	store := mysqlstore.NewSessionStore(db)
	if err := store.Create(context.Background(), active); err != nil {
		t.Fatalf("create refresh-logout session: %v", err)
	}

	tokenState := &fakeTokenState{}
	rotator := sessionapp.NewRotator(
		db,
		store,
		tokenState,
		sessionapp.NewInvalidator(db),
		15*time.Minute,
		24*time.Hour,
	)
	start := make(chan struct{})
	rotationResult := make(chan error, 1)
	logoutResult := make(chan error, 1)
	go func() {
		<-start
		_, err := rotator.Rotate(
			context.Background(),
			sessionapp.RotationRequest{
				UserID:             userID,
				CurrentRefreshHash: active.CurrentRefreshHash,
				RefreshExpiresAt:   active.ExpiresAt,
			},
			func(context.Context) (sessionapp.RotationTokens, error) {
				return sessionapp.RotationTokens{
					AccessToken:  "store_refresh_logout_new_access",
					RefreshToken: "store_refresh_logout_new_refresh",
					AccessJTI:    "store_refresh_logout_new_jti",
				}, nil
			},
		)
		rotationResult <- err
	}()
	go func() {
		<-start
		logoutResult <- store.RevokeByAccessJTI(
			context.Background(),
			userID,
			active.AccessJTI,
		)
	}()
	close(start)

	rotationErr := <-rotationResult
	if logoutErr := <-logoutResult; logoutErr != nil {
		t.Fatalf("logout race error: %v", logoutErr)
	}
	if rotationErr != nil && !errors.Is(rotationErr, apperror.ErrSessionExpired) {
		t.Fatalf("refresh race error = %v, want success or session expired", rotationErr)
	}

	var state struct {
		CurrentRefreshHash string       `db:"current_refresh_hash"`
		RevokedAt          sql.NullTime `db:"revoked_at"`
	}
	if err := db.Get(&state, `
		SELECT current_refresh_hash, revoked_at
		FROM sessions
		WHERE id = ?`,
		active.ID,
	); err != nil {
		t.Fatalf("read refresh-logout outcome: %v", err)
	}
	if rotationErr == nil {
		if state.CurrentRefreshHash != "store_refresh_logout_new_refresh" {
			t.Fatalf(
				"refresh winner current hash = %q, want rotated hash",
				state.CurrentRefreshHash,
			)
		}
		var history int
		if err := db.Get(&history, `
			SELECT COUNT(*)
			FROM refresh_token_history
			WHERE token_hash = ?`,
			active.CurrentRefreshHash,
		); err != nil {
			t.Fatalf("read refresh-logout history: %v", err)
		}
		if history != 1 {
			t.Fatalf("refresh winner history rows = %d, want 1", history)
		}
		return
	}
	if !state.RevokedAt.Valid {
		t.Fatal("logout winner did not durably revoke the session")
	}
}

func TestObservedClientProfilesDoNotCollapseSameOSAndBrowser(t *testing.T) {
	db := openIntegrationDB(t)
	userID := insertAccountFixture(t, db, "client_profiles")
	store := mysqlstore.NewClientProfileStore(db)
	osName := "Windows"
	browser := "Chrome"
	deviceType := "desktop"
	ip := "127.0.0.1"
	firstUA := "Mozilla/5.0 workstation-a Chrome/149"
	secondUA := "Mozilla/5.0 workstation-b Chrome/149"

	first := &mysqlstore.ClientProfile{
		UserID:     userID,
		DeviceName: &firstUA,
		DeviceType: &deviceType,
		OS:         &osName,
		Browser:    &browser,
		IPAddress:  &ip,
	}
	second := &mysqlstore.ClientProfile{
		UserID:     userID,
		DeviceName: &secondUA,
		DeviceType: &deviceType,
		OS:         &osName,
		Browser:    &browser,
		IPAddress:  &ip,
	}
	if err := store.Observe(context.Background(), first); err != nil {
		t.Fatalf("observe first client profile: %v", err)
	}
	if err := store.Observe(context.Background(), second); err != nil {
		t.Fatalf("observe second client profile: %v", err)
	}
	if first.ID == second.ID {
		t.Fatalf("same OS/browser observations collapsed to profile %d", first.ID)
	}
}

type fakeTokenState struct {
	blacklistErr error
	markErr      error
	reused       bool
}

func (f *fakeTokenState) BlacklistJTI(context.Context, string, time.Duration) error {
	return f.blacklistErr
}

func (f *fakeTokenState) IsRefreshReuseMarked(context.Context, string) (bool, error) {
	return f.reused, nil
}

func (f *fakeTokenState) MarkRefreshReuse(context.Context, string, time.Duration) error {
	return f.markErr
}

func openIntegrationDB(t *testing.T) *sqlx.DB {
	t.Helper()

	name := os.Getenv("UAM_STORE_TEST_DB_NAME")
	if !strings.HasPrefix(name, "uam_store_test_") {
		t.Skip("disposable store database is not configured")
	}
	cfg := mysql.Config{
		User:                 os.Getenv("UAM_STORE_TEST_DB_USER"),
		Passwd:               os.Getenv("UAM_STORE_TEST_DB_PASSWORD"),
		Net:                  "tcp",
		Addr:                 os.Getenv("UAM_STORE_TEST_DB_ADDR"),
		DBName:               name,
		ParseTime:            true,
		Loc:                  time.UTC,
		AllowNativePasswords: true,
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:3306"
	}
	db, err := sqlx.Connect("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("connect store integration database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func insertAccountFixture(t *testing.T, db *sqlx.DB, suffix string) uint64 {
	t.Helper()
	result, err := db.Exec(`
		INSERT INTO users (
			username, email, password_hash, lifecycle_state, email_verified,
			password_change_required, auth_version
		) VALUES (?, ?, 'hash', 'active', 1, 0, 0)`,
		"store_"+suffix,
		"store_"+suffix+"@example.test",
	)
	if err != nil {
		t.Fatalf("insert account fixture: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read account fixture id: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO user_profiles (
			user_id, full_name, phone, date_of_birth
		) VALUES (?, 'Store Integration User', '1', '1990-01-01')`,
		id,
	); err != nil {
		t.Fatalf("insert profile fixture: %v", err)
	}
	return uint64(id)
}

func insertSessionFixture(t *testing.T, db *sqlx.DB, userID uint64, suffix string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO sessions (
			user_id, current_refresh_hash, access_jti, expires_at
		) VALUES (?, ?, ?, '2030-01-01')`,
		userID,
		"refresh_"+suffix,
		"jti_"+suffix,
	)
	if err != nil {
		t.Fatalf("insert session fixture: %v", err)
	}
}

func assertAccountState(
	t *testing.T,
	db *sqlx.DB,
	userID uint64,
	wantLifecycle accountstate.Lifecycle,
	wantVersion uint64,
	wantSessions int,
) {
	t.Helper()
	var got struct {
		Lifecycle   accountstate.Lifecycle `db:"lifecycle_state"`
		AuthVersion uint64                 `db:"auth_version"`
	}
	if err := db.Get(&got,
		"SELECT lifecycle_state, auth_version FROM users WHERE id = ?",
		userID,
	); err != nil {
		t.Fatalf("load account state: %v", err)
	}
	if got.Lifecycle != wantLifecycle || got.AuthVersion != wantVersion {
		t.Fatalf("account state = %+v, want lifecycle=%s version=%d", got, wantLifecycle, wantVersion)
	}
	var sessions int
	if err := db.Get(&sessions, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", userID); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != wantSessions {
		t.Fatalf("sessions = %d, want %d", sessions, wantSessions)
	}
}

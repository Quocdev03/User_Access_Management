//go:build integration

package auth_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/quocdev03/user-access-management/internal/auth"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	"github.com/quocdev03/user-access-management/internal/session"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func TestMFAEnrollmentLoginConcurrencyRecoveryAndDisable(t *testing.T) {
	redisAddress := os.Getenv("UAM_REDIS_TEST_ADDR")
	if redisAddress == "" {
		t.Skip("UAM_REDIS_TEST_ADDR is not configured")
	}
	db := openAuthIntegrationDB(t)
	redisClient := redis.NewClient(&redis.Options{Addr: redisAddress})
	t.Cleanup(func() { _ = redisClient.Close() })

	registration, verification, mailCodec := authFixture(t, db)
	suffix := strings.ReplaceAll(
		time.Now().UTC().Format("150405.000000000"),
		".",
		"",
	)
	email := "mfa_integration_" + suffix + "@example.test"
	password := "MFATest!Password1"
	registered, err := registration.Register(
		context.Background(),
		auth.RegisterCommand{
			Username:    "mfa_integration_" + suffix,
			Email:       email,
			Password:    password,
			FullName:    "MFA Integration",
			Phone:       "0900000011",
			DateOfBirth: "1990-01-11",
		},
	)
	if err != nil {
		t.Fatalf("Register(): %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM users WHERE id = ?`, registered.ID)
	})
	if err := verification.Verify(
		context.Background(),
		email,
		verificationOTP(t, db, mailCodec, registered.ID),
	); err != nil {
		t.Fatalf("Verify(): %v", err)
	}

	accounts := mysqlstore.NewAccountStore(db)
	profiles := mysqlstore.NewProfileStore(db)
	roles := mysqlstore.NewRoleStore(db)
	audits := mysqlstore.NewAuditStore(db)
	mfaStore := mysqlstore.NewMFAStore(db)
	challenges := redisstore.NewMFAChallengeStore(redisClient)
	tokenStore := redisstore.NewTokenStore(redisClient)
	sessionInvalidator := session.NewInvalidator(db)
	issuer := session.NewIssuer(
		mysqlstore.NewSessionStore(db),
		mysqlstore.NewClientProfileStore(db),
		tokenStore,
		sessionInvalidator,
		10,
		15*time.Minute,
		24*time.Hour,
	)
	secretCodec, err := auth.NewMFASecretCodec(
		"v1",
		map[string][]byte{
			"v1": []byte("mfa-integration-encryption-key-1"),
		},
	)
	if err != nil {
		t.Fatalf("NewMFASecretCodec(): %v", err)
	}
	tokenPolicy := auth.TokenPolicy{
		JWTSecret:     "mfa-integration-jwt-secret",
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 24 * time.Hour,
	}
	mfa := auth.NewMFA(
		auth.MFADependencies{
			DB:                 db,
			Accounts:           accounts,
			Profiles:           profiles,
			Roles:              roles,
			Audits:             audits,
			Store:              mfaStore,
			Challenges:         challenges,
			Issuer:             issuer,
			AuthInvalidator:    mysqlstore.NewAuthInvalidator(db),
			SessionInvalidator: sessionInvalidator,
			Codec:              secretCodec,
		},
		auth.MFAPolicy{
			Issuer:            "MFA Integration",
			ChallengeTTL:      2 * time.Minute,
			MaxAttempts:       3,
			RecoveryCodeCount: 10,
			MaxFailedAttempts: 5,
			LockDuration:      30 * time.Minute,
			TokenPolicy:       tokenPolicy,
		},
	)
	login := auth.NewLogin(
		db,
		accounts,
		profiles,
		roles,
		audits,
		issuer,
		mfa,
		auth.LoginPolicy{
			TokenPolicy:       tokenPolicy,
			MaxFailedAttempts: 5,
			LockDuration:      30 * time.Minute,
		},
		zap.NewNop(),
	)

	setup, err := mfa.Setup(
		context.Background(),
		registered.ID,
		password,
		auth.PasswordMetadata{},
	)
	if err != nil {
		t.Fatalf("Setup(): %v", err)
	}
	if setup.Secret == "" || !strings.Contains(setup.EnrollmentURI, setup.Secret) {
		t.Fatalf("setup result = %+v", setup)
	}
	confirmCode := integrationTOTPCode(
		t,
		setup.Secret,
		time.Now().UTC().Add(-30*time.Second),
	)
	recoveryCodes, err := mfa.Confirm(
		context.Background(),
		registered.ID,
		1,
		confirmCode,
		auth.PasswordMetadata{},
	)
	if err != nil {
		t.Fatalf("Confirm(): %v", err)
	}
	if len(recoveryCodes) != 10 {
		t.Fatalf("recovery codes = %d, want 10", len(recoveryCodes))
	}
	assertScalar(
		t,
		db,
		`SELECT COUNT(*) FROM users WHERE id = ? AND auth_version = 2`,
		registered.ID,
		1,
	)

	challengeResult, err := login.Authenticate(
		context.Background(),
		auth.LoginCommand{
			Email:     email,
			Password:  password,
			IPAddress: "127.0.0.1",
			UserAgent: "mfa-integration-test",
		},
	)
	if err != nil {
		t.Fatalf("Authenticate(MFA): %v", err)
	}
	if !challengeResult.MFARequired ||
		challengeResult.MFAChallenge == "" ||
		challengeResult.AccessToken != "" {
		t.Fatalf("MFA login result = %+v", challengeResult)
	}
	loginCode := integrationTOTPCode(t, setup.Secret, time.Now().UTC())
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := mfa.VerifyLogin(context.Background(), auth.MFALoginCommand{
				Challenge: challengeResult.MFAChallenge,
				Code:      loginCode,
				IPAddress: "127.0.0.1",
				UserAgent: "mfa-integration-test",
			})
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	rejections := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, apperror.ErrMFAInvalid):
			rejections++
		default:
			t.Fatalf("VerifyLogin() concurrent error: %v", err)
		}
	}
	if successes != 1 || rejections != 1 {
		t.Fatalf("MFA login results success=%d rejected=%d", successes, rejections)
	}
	assertScalar(
		t,
		db,
		`SELECT COUNT(*) FROM sessions WHERE user_id = ?`,
		registered.ID,
		1,
	)

	recoveryChallenge := authenticateMFAChallenge(t, login, email, password)
	if _, err := mfa.VerifyLogin(context.Background(), auth.MFALoginCommand{
		Challenge: recoveryChallenge,
		Code:      recoveryCodes[0],
	}); err != nil {
		t.Fatalf("VerifyLogin(recovery): %v", err)
	}
	reusedChallenge := authenticateMFAChallenge(t, login, email, password)
	if _, err := mfa.VerifyLogin(context.Background(), auth.MFALoginCommand{
		Challenge: reusedChallenge,
		Code:      recoveryCodes[0],
	}); !errors.Is(err, apperror.ErrMFAInvalid) {
		t.Fatalf("reused recovery code error = %v", err)
	}

	newRecoveryCodes, err := mfa.RegenerateRecoveryCodes(
		context.Background(),
		registered.ID,
		password,
		recoveryCodes[1],
		auth.PasswordMetadata{},
	)
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes(): %v", err)
	}
	if len(newRecoveryCodes) != 10 {
		t.Fatalf("new recovery codes = %d, want 10", len(newRecoveryCodes))
	}
	assertScalar(
		t,
		db,
		`SELECT COUNT(*) FROM sessions WHERE user_id = ?`,
		registered.ID,
		0,
	)
	if err := mfa.Disable(
		context.Background(),
		registered.ID,
		password,
		newRecoveryCodes[0],
		auth.PasswordMetadata{},
	); err != nil {
		t.Fatalf("Disable(): %v", err)
	}
	status, err := mfa.Status(context.Background(), registered.ID)
	if err != nil || status.Enabled {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
}

func authenticateMFAChallenge(
	t *testing.T,
	login *auth.Login,
	email string,
	password string,
) string {
	t.Helper()
	result, err := login.Authenticate(context.Background(), auth.LoginCommand{
		Email:     email,
		Password:  password,
		IPAddress: "127.0.0.1",
		UserAgent: "mfa-integration-test",
	})
	if err != nil {
		t.Fatalf("Authenticate(): %v", err)
	}
	if !result.MFARequired || result.MFAChallenge == "" {
		t.Fatalf("Authenticate() result = %+v", result)
	}
	return result.MFAChallenge
}

func integrationTOTPCode(
	t *testing.T,
	secret string,
	at time.Time,
) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom(): %v", err)
	}
	return code
}

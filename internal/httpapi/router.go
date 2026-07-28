// Package httpapi owns the public HTTP transport, middleware, and route wiring.
package httpapi

import (
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	accessapp "github.com/quocdev03/user-access-management/internal/access"
	accountapp "github.com/quocdev03/user-access-management/internal/account"
	authapp "github.com/quocdev03/user-access-management/internal/auth"
	"github.com/quocdev03/user-access-management/internal/blob"
	"github.com/quocdev03/user-access-management/internal/config"
	mailmessage "github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	sessionapp "github.com/quocdev03/user-access-management/internal/session"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func Setup(
	db *sqlx.DB,
	redisClient *redis.Client,
	logger *zap.Logger,
	cfg *config.Config,
	blobStore blob.Store,
) *gin.Engine {
	r := gin.New()
	httpMetrics := &HTTPMetrics{}
	r.Use(RequestObservability(logger, httpMetrics))
	r.Use(Recovery(logger))

	// ClientIP: chỉ tin X-Forwarded-For khi TRUSTED_PROXIES được set tường minh.
	// Không default trust-all (0.0.0.0/0) — tránh spoof IP / bypass rate limit.
	if len(cfg.App.TrustedProxies) > 0 {
		if err := r.SetTrustedProxies(cfg.App.TrustedProxies); err != nil {
			logger.Fatal("Invalid trusted proxy configuration", zap.Error(err))
		}
	} else {
		if err := r.SetTrustedProxies(nil); err != nil {
			logger.Fatal("Failed to disable trusted proxies", zap.Error(err))
		}
	}

	r.Use(CORSMiddleware(cfg))

	sessionStore := mysqlstore.NewSessionStore(db)
	clientProfileStore := mysqlstore.NewClientProfileStore(db)
	accountStore := mysqlstore.NewAccountStore(db)
	accessStore := mysqlstore.NewAccessStore(db)
	profileStore := mysqlstore.NewProfileStore(db)
	roleStore := mysqlstore.NewRoleStore(db)
	challengeStore := mysqlstore.NewVerificationChallengeStore(db)
	emailChangeStore := mysqlstore.NewEmailChangeStore(db)
	outboxStore := mysqlstore.NewOutboxStore(db)
	tokenStore := redisstore.NewTokenStore(redisClient)
	authInvalidator := sessionapp.NewInvalidator(db)
	sessionManager := sessionapp.NewManager(
		db,
		sessionStore,
		clientProfileStore,
		tokenStore,
		authInvalidator,
		cfg.JWT.AccessExpiry,
	)
	sessionIssuer := sessionapp.NewIssuer(
		sessionStore,
		clientProfileStore,
		tokenStore,
		authInvalidator,
		cfg.Security.MaxSessionsPerUser,
		cfg.JWT.AccessExpiry,
		cfg.JWT.RefreshExpiry,
	)
	sessionRotator := sessionapp.NewRotator(
		db,
		sessionStore,
		tokenStore,
		authInvalidator,
		cfg.JWT.AccessExpiry,
		cfg.JWT.RefreshExpiry,
	)
	passwordResetStore := mysqlstore.NewPasswordResetStore(db)
	auditLogRepo := mysqlstore.NewAuditStore(db)
	mfaStore := mysqlstore.NewMFAStore(db)
	mfaChallengeStore := redisstore.NewMFAChallengeStore(redisClient)
	accountAuthInvalidator := mysqlstore.NewAuthInvalidator(db)
	secretCodec, err := mailmessage.NewSecretCodec(cfg.Security.OTPPepper)
	if err != nil {
		logger.Fatal("Failed to initialize secret payload codec", zap.Error(err))
	}
	mfaSecretCodec, err := authapp.NewMFASecretCodec(
		cfg.MFA.ActiveKeyVersion,
		cfg.MFA.EncryptionKeys,
	)
	if err != nil {
		logger.Fatal("Failed to initialize MFA secret codec", zap.Error(err))
	}
	emailVerification := authapp.NewEmailVerification(
		db,
		accountStore,
		challengeStore,
		outboxStore,
		accountAuthInvalidator,
		secretCodec,
		cfg.Security.OTPPepper,
		cfg.Security.OTPExpiry,
		cfg.Security.OTPMaxAttempts,
	)
	registration := authapp.NewRegistration(
		db,
		accountStore,
		profileStore,
		roleStore,
		emailVerification,
	)
	tokenPolicy := authapp.TokenPolicy{
		JWTSecret:     cfg.JWT.Secret,
		AccessExpiry:  cfg.JWT.AccessExpiry,
		RefreshExpiry: cfg.JWT.RefreshExpiry,
	}
	mfa := authapp.NewMFA(
		authapp.MFADependencies{
			DB:                 db,
			Accounts:           accountStore,
			Profiles:           profileStore,
			Roles:              roleStore,
			Audits:             auditLogRepo,
			Store:              mfaStore,
			Challenges:         mfaChallengeStore,
			Issuer:             sessionIssuer,
			AuthInvalidator:    accountAuthInvalidator,
			SessionInvalidator: authInvalidator,
			Codec:              mfaSecretCodec,
		},
		authapp.MFAPolicy{
			Issuer:            cfg.MFA.Issuer,
			ChallengeTTL:      cfg.MFA.ChallengeTTL,
			MaxAttempts:       cfg.MFA.MaxAttempts,
			RecoveryCodeCount: cfg.MFA.RecoveryCodeCount,
			MaxFailedAttempts: cfg.Security.MaxFailedAttempts,
			LockDuration:      cfg.Security.LockDuration,
			TokenPolicy:       tokenPolicy,
		},
	)
	login := authapp.NewLogin(
		db,
		accountStore,
		profileStore,
		roleStore,
		auditLogRepo,
		sessionIssuer,
		mfa,
		authapp.LoginPolicy{
			TokenPolicy:       tokenPolicy,
			MaxFailedAttempts: cfg.Security.MaxFailedAttempts,
			LockDuration:      cfg.Security.LockDuration,
		},
		logger,
	)
	refresh := authapp.NewRefresh(
		accountStore,
		roleStore,
		sessionRotator,
		tokenPolicy,
		logger,
	)
	logout := authapp.NewLogout(
		sessionStore,
		tokenStore,
		authInvalidator,
		logger,
	)
	password := authapp.NewPassword(
		db,
		accountStore,
		passwordResetStore,
		outboxStore,
		auditLogRepo,
		accountAuthInvalidator,
		secretCodec,
		emailChangeStore,
		authapp.PasswordPolicy{
			ResetExpiry:       cfg.Security.PasswordResetExpiry,
			MaxFailedAttempts: cfg.Security.MaxFailedAttempts,
			LockDuration:      cfg.Security.LockDuration,
		},
	)
	accountProfile := accountapp.NewProfile(
		db,
		accountStore,
		profileStore,
		roleStore,
		auditLogRepo,
		blobStore,
	)
	accountEmail := accountapp.NewEmail(
		db,
		accountStore,
		emailChangeStore,
		challengeStore,
		passwordResetStore,
		outboxStore,
		auditLogRepo,
		accountAuthInvalidator,
		secretCodec,
		cfg.Security.OTPPepper,
		accountapp.EmailPolicy{
			Expiry:      cfg.Security.EmailChangeExpiry,
			MaxAttempts: cfg.Security.OTPMaxAttempts,
		},
	)
	accountAvatar := accountapp.NewAvatar(
		db,
		profileStore,
		auditLogRepo,
		blobStore,
		logger,
	)
	accessUsers := accessapp.NewUsers(
		db,
		accessStore,
		accountStore,
		profileStore,
		emailChangeStore,
		passwordResetStore,
		outboxStore,
		auditLogRepo,
		accountAuthInvalidator,
		secretCodec,
		blobStore,
		cfg.Security.PasswordResetExpiry,
	)
	accessRoles := accessapp.NewRoles(
		db,
		accessStore,
		accountStore,
		auditLogRepo,
		accountAuthInvalidator,
	)
	accessAudit := accessapp.NewAudit(auditLogRepo)
	accessAuthorizer := accessapp.NewAuthorizer(accessStore)

	authHandler := NewAuthHandler(
		registration,
		emailVerification,
		login,
		refresh,
		logout,
		password,
		mfa,
	)
	userHandler := NewUserHandler(
		accountProfile,
		accountEmail,
		accountAvatar,
		sessionManager,
	)
	adminHandler := NewAdminHandler(accessUsers, accessRoles, accessAudit)

	authMiddleware := AuthMiddleware(cfg, accountStore, tokenStore, logger)

	setupHealthRoutes(r, db, redisClient, cfg.Observability.ReadinessTimeout, logger)
	if cfg.App.Env != "production" || cfg.Observability.MetricsToken != "" {
		r.GET(
			"/metrics",
			MetricsHandler(
				httpMetrics,
				db,
				redisClient,
				cfg.Observability.MetricsToken,
			),
		)
	}

	limiter := redisstore.NewLimiter(redisClient)
	v1 := r.Group("/api/v1")
	v1.Use(BodyLimitMiddleware(
		cfg.Security.JSONMaxBytes,
		cfg.Security.MultipartMaxBytes,
	))
	v1.Use(RateLimitMiddleware(
		limiter,
		httpMetrics,
		"global",
		cfg.Security.RateLimitRequests,
		cfg.Security.RateLimitRequests*3,
		cfg.Security.RateLimitWindow,
		cfg.Security.RateLimitBanDuration,
	))
	{
		setupAuthRoutes(
			v1,
			authHandler,
			authMiddleware,
			limiter,
			httpMetrics,
			cfg.Security.RateLimitBanDuration,
		)
		setupUserRoutes(
			v1,
			userHandler,
			authMiddleware,
			limiter,
			httpMetrics,
			cfg.Security.RateLimitBanDuration,
		)
		setupAdminRoutes(v1, adminHandler, authMiddleware, accessAuthorizer)
	}
	if cfg.Blob.Provider == "local" {
		r.Static("/uploads", cfg.Blob.LocalRoot)
	}
	if cfg.App.Env != "production" {
		r.StaticFile("/", "./ui_test/index.html")
		r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	return r
}

// Package config cung cấp các cấu trúc dữ liệu và hàm tiện ích để nạp cấu hình hệ thống.
// Package này sử dụng Viper để đọc cấu hình từ file .env hoặc trực tiếp từ biến môi trường,
// giúp việc quản lý thiết lập cho ứng dụng (Database, Redis, JWT, Mail, Security) trở nên tập trung và nhất quán.
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	netmail "net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

// Config chứa toàn bộ cấu hình tổng thể của ứng dụng, bao gồm các cấu hình thành phần.
type Config struct {
	App           AppConfig      `validate:"required"`
	Database      DatabaseConfig `validate:"required"`
	Redis         RedisConfig    `validate:"required"`
	JWT           JWTConfig      `validate:"required"`
	Mail          MailConfig     `validate:"required"`
	Blob          BlobConfig     `validate:"required"`
	Security      SecurityConfig `validate:"required"`
	MFA           MFAConfig      `validate:"required"`
	Cleanup       CleanupConfig  `validate:"required"`
	Outbox        OutboxConfig   `validate:"required"`
	Observability ObservabilityConfig
}

// AppConfig định nghĩa các thông số cơ bản để chạy ứng dụng (Môi trường, Cổng, URL frontend).
type AppConfig struct {
	Env            string
	Port           string
	FrontendURL    string
	TrustedProxies []string
}

// DatabaseConfig định nghĩa thông số kết nối tới cơ sở dữ liệu (MySQL).
type DatabaseConfig struct {
	Host             string `validate:"required"`
	Port             string `validate:"required"`
	Name             string `validate:"required"`
	User             string `validate:"required"`
	Password         string `validate:"required"`
	TLSMode          string
	TLSCAFile        string
	TLSAllowInsecure bool
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxLifetime  time.Duration
	ConnMaxIdleTime  time.Duration
}

// RedisConfig định nghĩa thông số kết nối tới Redis (dùng cho Session, Rate Limit).
type RedisConfig struct {
	Host         string
	Port         string
	Password     string
	PoolSize     int
	MinIdleConns int
}

// JWTConfig lưu trữ khóa bí mật và thời gian sống (TTL) của các token xác thực.
type JWTConfig struct {
	Secret        string        `validate:"required,min=16"`
	AccessExpiry  time.Duration `validate:"required"`
	RefreshExpiry time.Duration `validate:"required"`
}

// MailConfig định nghĩa thông số kết nối tới máy chủ SMTP để gửi email (OTP, Verify).
type MailConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
}

type BlobConfig struct {
	Provider        string
	LocalRoot       string
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	PublicBaseURL   string
	ForcePathStyle  bool
}

// SecurityConfig chứa các ngưỡng cấu hình liên quan đến bảo mật chống Spam và Brute-force.
type SecurityConfig struct {
	RateLimitRequests    int
	RateLimitWindow      time.Duration
	MaxFailedAttempts    int
	LockDuration         time.Duration
	OTPExpiry            time.Duration
	OTPMaxAttempts       int
	OTPPepper            string
	MaxSessionsPerUser   int // 0 = unlimited
	RateLimitBanDuration time.Duration
	PasswordResetExpiry  time.Duration
	EmailChangeExpiry    time.Duration
	JSONMaxBytes         int64
	MultipartMaxBytes    int64
}

type MFAConfig struct {
	Issuer            string
	ActiveKeyVersion  string
	EncryptionKeys    map[string][]byte
	ChallengeTTL      time.Duration
	MaxAttempts       int
	RecoveryCodeCount int
}

// CleanupConfig — worker dọn row hết hạn (session/OTP/reset) + optional audit retention.
type CleanupConfig struct {
	Interval        time.Duration // default 1h
	BatchSize       int           // default 1000
	TableBudget     int           // maximum rows per table and run
	Timeout         time.Duration // default 2m per run
	LeaseTTL        time.Duration // must exceed Timeout
	OutboxRetention time.Duration
	AuditRetention  time.Duration // 0 = không xóa audit
}

type OutboxConfig struct {
	PollInterval  time.Duration
	BatchSize     int
	ClaimTTL      time.Duration
	Timeout       time.Duration
	MaxConcurrent int
}

type ObservabilityConfig struct {
	ReadinessTimeout time.Duration
	MetricsToken     string
}

// Load khởi tạo và nạp cấu hình từ file .env tại đường dẫn chỉ định hoặc lấy trực tiếp từ biến môi trường.
// Hàm này sử dụng cơ chế tự động ghi đè của Viper để ưu tiên biến môi trường (Environment Variables) hơn file .env.
// Trả về pointer của Config đã được nạp dữ liệu hoặc trả về lỗi nếu không thể phân tích cú pháp cấu hình.
func Load(path string) (*Config, error) {
	viper.SetConfigFile(path + "/.env")

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		}
	}

	cfg := &Config{
		App: AppConfig{
			Env:            strings.ToLower(strings.TrimSpace(viper.GetString("APP_ENV"))),
			Port:           strings.TrimSpace(viper.GetString("APP_PORT")),
			FrontendURL:    strings.TrimSpace(viper.GetString("APP_FRONTEND_URL")),
			TrustedProxies: splitCSV(viper.GetString("TRUSTED_PROXIES")),
		},
		Database: DatabaseConfig{
			Host:             strings.TrimSpace(viper.GetString("DB_HOST")),
			Port:             strings.TrimSpace(viper.GetString("DB_PORT")),
			Name:             strings.TrimSpace(viper.GetString("DB_NAME")),
			User:             strings.TrimSpace(viper.GetString("DB_USER")),
			Password:         viper.GetString("DB_PASSWORD"),
			TLSMode:          strings.ToLower(strings.TrimSpace(viper.GetString("DB_TLS_MODE"))),
			TLSCAFile:        strings.TrimSpace(viper.GetString("DB_TLS_CA_FILE")),
			TLSAllowInsecure: viper.GetBool("DB_TLS_ALLOW_INSECURE"),
			MaxOpenConns:     viper.GetInt("DB_MAX_OPEN_CONNS"),
			MaxIdleConns:     viper.GetInt("DB_MAX_IDLE_CONNS"),
			ConnMaxLifetime:  viper.GetDuration("DB_CONN_MAX_LIFETIME"),
			ConnMaxIdleTime:  viper.GetDuration("DB_CONN_MAX_IDLE_TIME"),
		},
		Redis: RedisConfig{
			Host:         strings.TrimSpace(viper.GetString("REDIS_HOST")),
			Port:         strings.TrimSpace(viper.GetString("REDIS_PORT")),
			Password:     viper.GetString("REDIS_PASSWORD"),
			PoolSize:     viper.GetInt("REDIS_POOL_SIZE"),
			MinIdleConns: viper.GetInt("REDIS_MIN_IDLE_CONNS"),
		},
		JWT: JWTConfig{
			Secret:        viper.GetString("JWT_SECRET"),
			AccessExpiry:  viper.GetDuration("JWT_ACCESS_EXPIRY"),
			RefreshExpiry: viper.GetDuration("JWT_REFRESH_EXPIRY"),
		},
		Mail: MailConfig{
			Host:     strings.TrimSpace(viper.GetString("SMTP_HOST")),
			Port:     viper.GetInt("SMTP_PORT"),
			User:     strings.TrimSpace(viper.GetString("SMTP_USER")),
			Password: viper.GetString("SMTP_PASSWORD"),
			From:     strings.TrimSpace(viper.GetString("SMTP_FROM")),
		},
		Blob: BlobConfig{
			Provider:        strings.ToLower(strings.TrimSpace(viper.GetString("BLOB_PROVIDER"))),
			LocalRoot:       strings.TrimSpace(viper.GetString("BLOB_LOCAL_ROOT")),
			Endpoint:        strings.TrimRight(strings.TrimSpace(viper.GetString("S3_ENDPOINT")), "/"),
			Region:          strings.TrimSpace(viper.GetString("S3_REGION")),
			Bucket:          strings.TrimSpace(viper.GetString("S3_BUCKET")),
			AccessKeyID:     strings.TrimSpace(viper.GetString("S3_ACCESS_KEY_ID")),
			SecretAccessKey: strings.TrimSpace(viper.GetString("S3_SECRET_ACCESS_KEY")),
			PublicBaseURL:   strings.TrimRight(strings.TrimSpace(viper.GetString("S3_PUBLIC_BASE_URL")), "/"),
			ForcePathStyle:  viper.GetBool("S3_FORCE_PATH_STYLE"),
		},
		Security: SecurityConfig{
			RateLimitRequests:    viper.GetInt("RATE_LIMIT_REQUESTS"),
			RateLimitWindow:      viper.GetDuration("RATE_LIMIT_WINDOW"),
			MaxFailedAttempts:    viper.GetInt("MAX_FAILED_ATTEMPTS"),
			LockDuration:         viper.GetDuration("LOCK_DURATION"),
			OTPExpiry:            viper.GetDuration("OTP_EXPIRY"),
			OTPMaxAttempts:       viper.GetInt("OTP_MAX_ATTEMPTS"),
			OTPPepper:            viper.GetString("OTP_PEPPER"),
			MaxSessionsPerUser:   viper.GetInt("MAX_SESSIONS_PER_USER"),
			RateLimitBanDuration: viper.GetDuration("RATE_LIMIT_BAN_DURATION"),
			PasswordResetExpiry:  viper.GetDuration("PASSWORD_RESET_EXPIRY"),
			EmailChangeExpiry:    viper.GetDuration("EMAIL_CHANGE_EXPIRY"),
			JSONMaxBytes:         viper.GetInt64("JSON_MAX_BYTES"),
			MultipartMaxBytes:    viper.GetInt64("MULTIPART_MAX_BYTES"),
		},
		MFA: MFAConfig{
			Issuer:            strings.TrimSpace(viper.GetString("MFA_ISSUER")),
			ActiveKeyVersion:  strings.TrimSpace(viper.GetString("MFA_ACTIVE_KEY_VERSION")),
			ChallengeTTL:      viper.GetDuration("MFA_CHALLENGE_TTL"),
			MaxAttempts:       viper.GetInt("MFA_MAX_ATTEMPTS"),
			RecoveryCodeCount: viper.GetInt("MFA_RECOVERY_CODE_COUNT"),
		},
		Cleanup: CleanupConfig{
			Interval:        viper.GetDuration("CLEANUP_INTERVAL"),
			BatchSize:       viper.GetInt("CLEANUP_BATCH_SIZE"),
			TableBudget:     viper.GetInt("CLEANUP_TABLE_BUDGET"),
			Timeout:         viper.GetDuration("CLEANUP_TIMEOUT"),
			LeaseTTL:        viper.GetDuration("CLEANUP_LEASE_TTL"),
			OutboxRetention: viper.GetDuration("OUTBOX_RETENTION"),
			AuditRetention:  viper.GetDuration("AUDIT_RETENTION"),
		},
		Outbox: OutboxConfig{
			PollInterval:  viper.GetDuration("OUTBOX_POLL_INTERVAL"),
			BatchSize:     viper.GetInt("OUTBOX_BATCH_SIZE"),
			ClaimTTL:      viper.GetDuration("OUTBOX_CLAIM_TTL"),
			Timeout:       viper.GetDuration("OUTBOX_TIMEOUT"),
			MaxConcurrent: viper.GetInt("OUTBOX_MAX_CONCURRENT"),
		},
		Observability: ObservabilityConfig{
			ReadinessTimeout: viper.GetDuration("READINESS_TIMEOUT"),
			MetricsToken:     viper.GetString("METRICS_TOKEN"),
		},
	}

	if cfg.App.Env == "" {
		cfg.App.Env = "development"
	}
	switch cfg.App.Env {
	case "development", "test", "staging", "production":
	default:
		return nil, fmt.Errorf("APP_ENV không được hỗ trợ: %q", cfg.App.Env)
	}
	if err := validatePort("APP_PORT", cfg.App.Port); err != nil {
		return nil, err
	}
	frontendURL, err := url.Parse(cfg.App.FrontendURL)
	if err != nil || frontendURL.Host == "" ||
		(frontendURL.Scheme != "http" && frontendURL.Scheme != "https") {
		return nil, fmt.Errorf("APP_FRONTEND_URL phải là absolute HTTP(S) URL")
	}
	if cfg.App.Env == "production" && frontendURL.Scheme != "https" {
		return nil, fmt.Errorf("APP_FRONTEND_URL phải dùng HTTPS trong production")
	}
	for _, proxy := range cfg.App.TrustedProxies {
		if net.ParseIP(proxy) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES chứa IP/CIDR không hợp lệ: %q", proxy)
		}
	}

	if err := validatePort("DB_PORT", cfg.Database.Port); err != nil {
		return nil, err
	}
	if cfg.Database.TLSMode == "" {
		cfg.Database.TLSMode = "disable"
	}
	switch cfg.Database.TLSMode {
	case "disable", "verify", "skip-verify":
	default:
		return nil, fmt.Errorf("DB_TLS_MODE phải là disable, verify hoặc skip-verify")
	}
	if cfg.Database.TLSMode != "verify" && cfg.Database.TLSCAFile != "" {
		return nil, fmt.Errorf("DB_TLS_CA_FILE chỉ dùng khi DB_TLS_MODE=verify")
	}
	if cfg.Database.TLSMode == "verify" && cfg.Database.TLSAllowInsecure {
		return nil, fmt.Errorf("DB_TLS_ALLOW_INSECURE không được bật khi DB_TLS_MODE=verify")
	}
	if cfg.App.Env == "production" &&
		cfg.Database.TLSMode != "verify" &&
		!cfg.Database.TLSAllowInsecure {
		return nil, fmt.Errorf(
			"production yêu cầu DB_TLS_MODE=verify; chỉ bật DB_TLS_ALLOW_INSECURE cho emergency có thời hạn",
		)
	}
	if cfg.Database.MaxOpenConns < 1 && viper.IsSet("DB_MAX_OPEN_CONNS") {
		return nil, fmt.Errorf("DB_MAX_OPEN_CONNS phải lớn hơn 0")
	}
	if cfg.Database.MaxOpenConns < 1 {
		cfg.Database.MaxOpenConns = 25
	}
	if cfg.Database.MaxIdleConns < 0 {
		return nil, fmt.Errorf("DB_MAX_IDLE_CONNS không được âm")
	}
	if !viper.IsSet("DB_MAX_IDLE_CONNS") {
		cfg.Database.MaxIdleConns = 10
	}
	if cfg.Database.MaxIdleConns > cfg.Database.MaxOpenConns {
		return nil, fmt.Errorf("DB_MAX_IDLE_CONNS không được lớn hơn DB_MAX_OPEN_CONNS")
	}
	if cfg.Database.ConnMaxLifetime < time.Second &&
		viper.IsSet("DB_CONN_MAX_LIFETIME") {
		return nil, fmt.Errorf("DB_CONN_MAX_LIFETIME phải ít nhất 1 giây")
	}
	if cfg.Database.ConnMaxLifetime < time.Second {
		cfg.Database.ConnMaxLifetime = 5 * time.Minute
	}
	if cfg.Database.ConnMaxIdleTime < time.Second &&
		viper.IsSet("DB_CONN_MAX_IDLE_TIME") {
		return nil, fmt.Errorf("DB_CONN_MAX_IDLE_TIME phải ít nhất 1 giây")
	}
	if cfg.Database.ConnMaxIdleTime < time.Second {
		cfg.Database.ConnMaxIdleTime = time.Minute
	}

	if strings.HasPrefix(cfg.Redis.Host, "redis://") ||
		strings.HasPrefix(cfg.Redis.Host, "rediss://") {
		redisURL, parseErr := url.Parse(cfg.Redis.Host)
		if parseErr != nil || redisURL.Host == "" {
			return nil, fmt.Errorf("REDIS_HOST URL không hợp lệ")
		}
	} else {
		if cfg.Redis.Host == "" {
			return nil, fmt.Errorf("REDIS_HOST bắt buộc")
		}
		if err := validatePort("REDIS_PORT", cfg.Redis.Port); err != nil {
			return nil, err
		}
	}
	if cfg.Redis.PoolSize < 1 && viper.IsSet("REDIS_POOL_SIZE") {
		return nil, fmt.Errorf("REDIS_POOL_SIZE phải lớn hơn 0")
	}
	if cfg.Redis.PoolSize < 1 {
		cfg.Redis.PoolSize = 20
	}
	if cfg.Redis.MinIdleConns < 0 || cfg.Redis.MinIdleConns > cfg.Redis.PoolSize {
		return nil, fmt.Errorf("REDIS_MIN_IDLE_CONNS phải nằm trong khoảng 0..REDIS_POOL_SIZE")
	}

	if cfg.Security.RateLimitRequests < 1 && viper.IsSet("RATE_LIMIT_REQUESTS") {
		return nil, fmt.Errorf("RATE_LIMIT_REQUESTS phải lớn hơn 0")
	}
	if cfg.Security.RateLimitRequests < 1 {
		cfg.Security.RateLimitRequests = 100
	}
	if cfg.Security.RateLimitBanDuration < time.Second &&
		viper.IsSet("RATE_LIMIT_BAN_DURATION") {
		return nil, fmt.Errorf("RATE_LIMIT_BAN_DURATION phải ít nhất 1 giây")
	}
	if cfg.Security.RateLimitBanDuration < time.Second {
		cfg.Security.RateLimitBanDuration = 15 * time.Minute
	}
	if cfg.Security.PasswordResetExpiry < time.Second &&
		viper.IsSet("PASSWORD_RESET_EXPIRY") {
		return nil, fmt.Errorf("PASSWORD_RESET_EXPIRY phải ít nhất 1 giây")
	}
	if cfg.Security.PasswordResetExpiry < time.Second {
		cfg.Security.PasswordResetExpiry = time.Hour
	}
	if cfg.Security.EmailChangeExpiry < time.Second &&
		viper.IsSet("EMAIL_CHANGE_EXPIRY") {
		return nil, fmt.Errorf("EMAIL_CHANGE_EXPIRY phải ít nhất 1 giây")
	}
	if cfg.Security.EmailChangeExpiry < time.Second {
		cfg.Security.EmailChangeExpiry = 15 * time.Minute
	}
	if cfg.Security.JSONMaxBytes < 1 && viper.IsSet("JSON_MAX_BYTES") {
		return nil, fmt.Errorf("JSON_MAX_BYTES phải lớn hơn 0")
	}
	if cfg.Security.JSONMaxBytes < 1 {
		cfg.Security.JSONMaxBytes = 64 << 10
	}
	if cfg.Security.MultipartMaxBytes < 1 && viper.IsSet("MULTIPART_MAX_BYTES") {
		return nil, fmt.Errorf("MULTIPART_MAX_BYTES phải lớn hơn 0")
	}
	if cfg.Security.MultipartMaxBytes < 1 {
		cfg.Security.MultipartMaxBytes = 3 << 20
	}
	if cfg.Security.MultipartMaxBytes < cfg.Security.JSONMaxBytes {
		return nil, fmt.Errorf("MULTIPART_MAX_BYTES không được nhỏ hơn JSON_MAX_BYTES")
	}
	if cfg.MFA.Issuer == "" {
		cfg.MFA.Issuer = "User Access Management"
	}
	if cfg.MFA.ChallengeTTL < time.Second && viper.IsSet("MFA_CHALLENGE_TTL") {
		return nil, fmt.Errorf("MFA_CHALLENGE_TTL phải ít nhất 1 giây")
	}
	if cfg.MFA.ChallengeTTL < time.Second {
		cfg.MFA.ChallengeTTL = 5 * time.Minute
	}
	if cfg.MFA.MaxAttempts < 1 && viper.IsSet("MFA_MAX_ATTEMPTS") {
		return nil, fmt.Errorf("MFA_MAX_ATTEMPTS phải lớn hơn 0")
	}
	if cfg.MFA.MaxAttempts < 1 {
		cfg.MFA.MaxAttempts = 5
	}
	if cfg.MFA.RecoveryCodeCount < 1 && viper.IsSet("MFA_RECOVERY_CODE_COUNT") {
		return nil, fmt.Errorf("MFA_RECOVERY_CODE_COUNT phải lớn hơn 0")
	}
	if cfg.MFA.RecoveryCodeCount < 1 {
		cfg.MFA.RecoveryCodeCount = 10
	}
	cfg.MFA.EncryptionKeys, err = parseMFAKeyRing(
		viper.GetString("MFA_ENCRYPTION_KEYS"),
	)
	if err != nil {
		return nil, err
	}
	if len(cfg.MFA.EncryptionKeys) == 0 {
		if cfg.App.Env == "production" || cfg.App.Env == "staging" {
			return nil, fmt.Errorf(
				"MFA_ENCRYPTION_KEYS bắt buộc khi APP_ENV=%s",
				cfg.App.Env,
			)
		}
		devKey := sha256.Sum256([]byte("uam-development-mfa:" + cfg.JWT.Secret))
		cfg.MFA.ActiveKeyVersion = "development-v1"
		cfg.MFA.EncryptionKeys = map[string][]byte{
			cfg.MFA.ActiveKeyVersion: devKey[:],
		}
	}
	if cfg.MFA.ActiveKeyVersion == "" {
		return nil, fmt.Errorf("MFA_ACTIVE_KEY_VERSION bắt buộc")
	}
	if _, ok := cfg.MFA.EncryptionKeys[cfg.MFA.ActiveKeyVersion]; !ok {
		return nil, fmt.Errorf(
			"MFA_ACTIVE_KEY_VERSION %q không có trong MFA_ENCRYPTION_KEYS",
			cfg.MFA.ActiveKeyVersion,
		)
	}
	if cfg.Observability.ReadinessTimeout < time.Second &&
		viper.IsSet("READINESS_TIMEOUT") {
		return nil, fmt.Errorf("READINESS_TIMEOUT phải ít nhất 1 giây")
	}
	if cfg.Observability.ReadinessTimeout < time.Second {
		cfg.Observability.ReadinessTimeout = 2 * time.Second
	}
	if cfg.Mail.Host != "" {
		if cfg.Mail.Port < 1 || cfg.Mail.Port > 65535 {
			return nil, fmt.Errorf("SMTP_PORT phải nằm trong khoảng 1..65535")
		}
		from, err := netmail.ParseAddress(strings.TrimSpace(cfg.Mail.From))
		if err != nil || from.Address != strings.TrimSpace(cfg.Mail.From) {
			return nil, fmt.Errorf("SMTP_FROM phải là một địa chỉ email không chứa display name")
		}
	}

	if cfg.Security.OTPPepper == "" {
		if cfg.App.Env == "production" {
			return nil, fmt.Errorf("OTP_PEPPER bắt buộc khi APP_ENV=production (không được fallback JWT_SECRET)")
		}
		// Dev/staging: fallback JWT để local chạy nhanh; production không dùng path này.
		cfg.Security.OTPPepper = cfg.JWT.Secret
	}
	if cfg.Blob.Provider == "" {
		cfg.Blob.Provider = "local"
	}
	if cfg.Blob.LocalRoot == "" {
		cfg.Blob.LocalRoot = "./uploads"
	}
	switch cfg.Blob.Provider {
	case "local":
		if cfg.App.Env == "production" {
			return nil, fmt.Errorf("BLOB_PROVIDER=s3 bắt buộc khi APP_ENV=production")
		}
	case "s3":
		if cfg.Blob.Region == "" ||
			cfg.Blob.Bucket == "" ||
			cfg.Blob.PublicBaseURL == "" {
			return nil, fmt.Errorf(
				"S3_REGION, S3_BUCKET và S3_PUBLIC_BASE_URL bắt buộc khi BLOB_PROVIDER=s3",
			)
		}
		if (cfg.Blob.AccessKeyID == "") != (cfg.Blob.SecretAccessKey == "") {
			return nil, fmt.Errorf(
				"S3_ACCESS_KEY_ID và S3_SECRET_ACCESS_KEY phải cùng được set hoặc cùng để trống",
			)
		}
		if cfg.Blob.Endpoint != "" {
			endpoint, err := url.Parse(cfg.Blob.Endpoint)
			if err != nil || endpoint.Host == "" ||
				(endpoint.Scheme != "http" && endpoint.Scheme != "https") {
				return nil, fmt.Errorf("S3_ENDPOINT phải là absolute HTTP(S) URL")
			}
			if cfg.App.Env == "production" && endpoint.Scheme != "https" {
				return nil, fmt.Errorf("S3_ENDPOINT phải dùng HTTPS trong production")
			}
		}
	default:
		return nil, fmt.Errorf("BLOB_PROVIDER không được hỗ trợ: %q", cfg.Blob.Provider)
	}
	if cfg.Security.MaxFailedAttempts <= 0 {
		if viper.IsSet("MAX_FAILED_ATTEMPTS") {
			return nil, fmt.Errorf("MAX_FAILED_ATTEMPTS phải lớn hơn 0")
		}
		cfg.Security.MaxFailedAttempts = 5
	}
	if cfg.Security.OTPMaxAttempts <= 0 {
		if viper.IsSet("OTP_MAX_ATTEMPTS") {
			return nil, fmt.Errorf("OTP_MAX_ATTEMPTS phải lớn hơn 0")
		}
		cfg.Security.OTPMaxAttempts = 5
	}
	if cfg.Security.MaxSessionsPerUser < 0 {
		return nil, fmt.Errorf("MAX_SESSIONS_PER_USER không được âm")
	}
	if !viper.IsSet("MAX_SESSIONS_PER_USER") {
		cfg.Security.MaxSessionsPerUser = 10
	}

	if cfg.Cleanup.Interval < time.Second {
		cfg.Cleanup.Interval = time.Hour
	}
	if cfg.Cleanup.BatchSize < 1 {
		cfg.Cleanup.BatchSize = 1000
	}
	if cfg.Cleanup.TableBudget < cfg.Cleanup.BatchSize {
		cfg.Cleanup.TableBudget = cfg.Cleanup.BatchSize * 5
	}
	if cfg.Cleanup.Timeout < time.Second {
		cfg.Cleanup.Timeout = 2 * time.Minute
	}
	if cfg.Cleanup.LeaseTTL <= cfg.Cleanup.Timeout {
		cfg.Cleanup.LeaseTTL = cfg.Cleanup.Timeout + time.Minute
	}
	if cfg.Cleanup.OutboxRetention < time.Hour {
		cfg.Cleanup.OutboxRetention = 7 * 24 * time.Hour
	}
	if cfg.Outbox.PollInterval < 100*time.Millisecond {
		cfg.Outbox.PollInterval = time.Second
	}
	if cfg.Outbox.BatchSize < 1 {
		cfg.Outbox.BatchSize = 20
	}
	if cfg.Outbox.ClaimTTL < time.Second {
		cfg.Outbox.ClaimTTL = 2 * time.Minute
	}
	if cfg.Outbox.Timeout < time.Second {
		cfg.Outbox.Timeout = 30 * time.Second
	}
	if cfg.Outbox.MaxConcurrent < 1 {
		cfg.Outbox.MaxConcurrent = 4
	}
	if cfg.Cleanup.AuditRetention < 0 {
		return nil, fmt.Errorf("AUDIT_RETENTION không được âm")
	}

	validate := validator.New()
	if err := validate.Struct(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Kiểm tra các giá trị thời gian để tránh lỗi do viper parse plain number thành nanoseconds
	if cfg.JWT.AccessExpiry < time.Second ||
		cfg.JWT.RefreshExpiry < time.Second ||
		cfg.Security.RateLimitWindow < time.Second ||
		cfg.Security.LockDuration < time.Second ||
		cfg.Security.OTPExpiry < time.Second ||
		cfg.Security.RateLimitBanDuration < time.Second ||
		cfg.Security.PasswordResetExpiry < time.Second ||
		cfg.Security.EmailChangeExpiry < time.Second ||
		cfg.MFA.ChallengeTTL < time.Second {
		return nil, fmt.Errorf("cấu hình thời gian (JWT_ACCESS_EXPIRY, RATE_LIMIT_WINDOW, v.v.) quá nhỏ (dưới 1s). Vui lòng đảm bảo file .env sử dụng suffix (ví dụ: '900s', '15m') thay vì số nguyên đơn thuần")
	}

	return cfg, nil
}

func parseMFAKeyRing(raw string) (map[string][]byte, error) {
	keys := map[string][]byte{}
	if strings.TrimSpace(raw) == "" {
		return keys, nil
	}
	for _, entry := range strings.Split(raw, ",") {
		version, encoded, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok || version == "" || encoded == "" {
			return nil, fmt.Errorf(
				"MFA_ENCRYPTION_KEYS phải có dạng version:base64[,version:base64]",
			)
		}
		if len(version) > 32 || strings.ContainsAny(version, "{} \t\r\n") {
			return nil, fmt.Errorf("MFA key version không hợp lệ: %q", version)
		}
		if _, exists := keys[version]; exists {
			return nil, fmt.Errorf("MFA key version bị trùng: %q", version)
		}
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode MFA key %q: %w", version, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("MFA key %q phải dài đúng 32 bytes", version)
		}
		keys[version] = key
	}
	return keys, nil
}

func validatePort(name, value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s phải là số trong khoảng 1..65535", name)
	}
	return nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

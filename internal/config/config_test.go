package config

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestLoadRejectsLocalBlobStorageInProduction(t *testing.T) {
	setProductionConfig(t)
	t.Setenv("BLOB_PROVIDER", "local")

	_, err := Load(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "BLOB_PROVIDER=s3") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadAcceptsS3WithWorkloadIdentity(t *testing.T) {
	setProductionConfig(t)
	t.Setenv("BLOB_PROVIDER", "s3")
	t.Setenv("S3_REGION", "auto")
	t.Setenv("S3_BUCKET", "uam-avatars")
	t.Setenv("S3_PUBLIC_BASE_URL", "https://avatars.example.test")

	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if cfg.Blob.Provider != "s3" || cfg.Blob.Bucket != "uam-avatars" {
		t.Fatalf("blob config = %+v", cfg.Blob)
	}
}

func TestLoadRejectsInsecureProductionS3Endpoint(t *testing.T) {
	setProductionConfig(t)
	t.Setenv("BLOB_PROVIDER", "s3")
	t.Setenv("S3_ENDPOINT", "http://object-storage.internal")
	t.Setenv("S3_REGION", "auto")
	t.Setenv("S3_BUCKET", "uam-avatars")
	t.Setenv("S3_PUBLIC_BASE_URL", "https://avatars.example.test")

	_, err := Load(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadRejectsInsecureProductionDatabaseTLS(t *testing.T) {
	setProductionConfig(t)
	setProductionBlobConfig(t)
	t.Setenv("DB_TLS_MODE", "skip-verify")

	_, err := Load(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "DB_TLS_MODE=verify") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadAllowsExplicitEmergencyDatabaseTLSOverride(t *testing.T) {
	setProductionConfig(t)
	setProductionBlobConfig(t)
	t.Setenv("DB_TLS_MODE", "skip-verify")
	t.Setenv("DB_TLS_ALLOW_INSECURE", "true")

	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if cfg.Database.TLSMode != "skip-verify" || !cfg.Database.TLSAllowInsecure {
		t.Fatalf("database TLS config = %+v", cfg.Database)
	}
}

func TestLoadRejectsInvalidPortAndPoolBudget(t *testing.T) {
	t.Run("port", func(t *testing.T) {
		setProductionConfig(t)
		setProductionBlobConfig(t)
		t.Setenv("APP_PORT", "70000")

		_, err := Load(t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "APP_PORT") {
			t.Fatalf("Load() error = %v", err)
		}
	})

	t.Run("pool", func(t *testing.T) {
		setProductionConfig(t)
		setProductionBlobConfig(t)
		t.Setenv("DB_MAX_OPEN_CONNS", "5")
		t.Setenv("DB_MAX_IDLE_CONNS", "6")

		_, err := Load(t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "DB_MAX_IDLE_CONNS") {
			t.Fatalf("Load() error = %v", err)
		}
	})
}

func TestLoadAppliesSecurityAndPoolDefaults(t *testing.T) {
	setProductionConfig(t)
	setProductionBlobConfig(t)

	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if cfg.Database.MaxOpenConns != 25 ||
		cfg.Database.MaxIdleConns != 10 ||
		cfg.Redis.PoolSize != 20 {
		t.Fatalf("pool defaults: database=%+v redis=%+v", cfg.Database, cfg.Redis)
	}
	if cfg.Security.JSONMaxBytes != 64<<10 ||
		cfg.Security.MultipartMaxBytes != 3<<20 ||
		cfg.Security.PasswordResetExpiry.String() != "1h0m0s" {
		t.Fatalf("security defaults = %+v", cfg.Security)
	}
	if cfg.MFA.ActiveKeyVersion != "v1" ||
		len(cfg.MFA.EncryptionKeys["v1"]) != 32 ||
		cfg.MFA.ChallengeTTL.String() != "5m0s" {
		t.Fatalf("MFA config = %+v", cfg.MFA)
	}
}

func TestLoadRejectsMissingOrMalformedProductionMFAKeys(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		setProductionConfig(t)
		setProductionBlobConfig(t)
		t.Setenv("MFA_ENCRYPTION_KEYS", "")

		_, err := Load(t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "MFA_ENCRYPTION_KEYS") {
			t.Fatalf("Load() error = %v", err)
		}
	})

	t.Run("wrong key length", func(t *testing.T) {
		setProductionConfig(t)
		setProductionBlobConfig(t)
		t.Setenv(
			"MFA_ENCRYPTION_KEYS",
			"v1:"+base64.StdEncoding.EncodeToString([]byte("short")),
		)

		_, err := Load(t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "32 bytes") {
			t.Fatalf("Load() error = %v", err)
		}
	})

	t.Run("active version missing", func(t *testing.T) {
		setProductionConfig(t)
		setProductionBlobConfig(t)
		t.Setenv("MFA_ACTIVE_KEY_VERSION", "v2")

		_, err := Load(t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "v2") {
			t.Fatalf("Load() error = %v", err)
		}
	})
}

func setProductionBlobConfig(t *testing.T) {
	t.Helper()
	t.Setenv("BLOB_PROVIDER", "s3")
	t.Setenv("S3_REGION", "auto")
	t.Setenv("S3_BUCKET", "uam-avatars")
	t.Setenv("S3_PUBLIC_BASE_URL", "https://avatars.example.test")
}

func setProductionConfig(t *testing.T) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	values := map[string]string{
		"APP_ENV":                "production",
		"APP_PORT":               "8080",
		"APP_FRONTEND_URL":       "https://app.example.test",
		"DB_HOST":                "db.example.test",
		"DB_PORT":                "3306",
		"DB_NAME":                "uam",
		"DB_USER":                "uam",
		"DB_PASSWORD":            "secret",
		"DB_TLS_MODE":            "verify",
		"REDIS_HOST":             "rediss://redis.example.test:6379",
		"JWT_SECRET":             "production-test-secret",
		"JWT_ACCESS_EXPIRY":      "15m",
		"JWT_REFRESH_EXPIRY":     "168h",
		"RATE_LIMIT_WINDOW":      "1m",
		"LOCK_DURATION":          "15m",
		"OTP_EXPIRY":             "5m",
		"OTP_PEPPER":             "production-test-pepper",
		"MFA_ACTIVE_KEY_VERSION": "v1",
		"MFA_ENCRYPTION_KEYS":    "v1:ZGV2LW9ubHktbWZhLWtleS0zMi1ieXRlcy0wMDAwMDA=",
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
}

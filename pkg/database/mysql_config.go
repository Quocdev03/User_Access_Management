package database

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/quocdev03/user-access-management/internal/config"
)

var mysqlTLSConfigSequence atomic.Uint64

func newMySQLConfig(cfg config.DatabaseConfig, multiStatements bool) (mysql.Config, error) {
	mysqlCfg := mysql.Config{
		User:                 cfg.User,
		Passwd:               cfg.Password,
		Net:                  "tcp",
		Addr:                 net.JoinHostPort(cfg.Host, cfg.Port),
		DBName:               cfg.Name,
		Collation:            "utf8mb4_unicode_ci",
		ParseTime:            true,
		Loc:                  time.UTC,
		Timeout:              10 * time.Second,
		AllowNativePasswords: true,
		MultiStatements:      multiStatements,
	}

	switch cfg.TLSMode {
	case "", "disable":
	case "skip-verify":
		mysqlCfg.TLSConfig = "skip-verify"
	case "verify":
		if cfg.TLSCAFile == "" {
			mysqlCfg.TLSConfig = "true"
			break
		}
		certificate, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return mysql.Config{}, fmt.Errorf("read MySQL CA file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certificate) {
			return mysql.Config{}, fmt.Errorf("MySQL CA file does not contain a valid PEM certificate")
		}
		name := fmt.Sprintf("uam-verified-%d", mysqlTLSConfigSequence.Add(1))
		if err := mysql.RegisterTLSConfig(name, &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: cfg.Host,
		}); err != nil {
			return mysql.Config{}, fmt.Errorf("register MySQL TLS config: %w", err)
		}
		mysqlCfg.TLSConfig = name
	default:
		return mysql.Config{}, fmt.Errorf("unsupported MySQL TLS mode %q", cfg.TLSMode)
	}

	return mysqlCfg, nil
}

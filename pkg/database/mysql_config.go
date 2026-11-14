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
)

// File này tạo DSN và TLS config an toàn cho MySQL.

var mysqlTLSConfigSequence atomic.Uint64

// newMySQLConfig tạo DSN, TLS registration và pool options từ cấu hình đã kiểm tra.
func newMySQLConfig(opts MySQLOptions, multiStatements bool) (mysql.Config, error) {
	mysqlCfg := mysql.Config{
		User:                 opts.User,
		Passwd:               opts.Password,
		Net:                  "tcp",
		Addr:                 net.JoinHostPort(opts.Host, opts.Port),
		DBName:               opts.Name,
		Collation:            "utf8mb4_unicode_ci",
		ParseTime:            true,
		Loc:                  time.UTC,
		Timeout:              10 * time.Second,
		AllowNativePasswords: true,
		MultiStatements:      multiStatements,
	}

	switch opts.TLSMode {
	case "", "disable":
	case "skip-verify":
		mysqlCfg.TLSConfig = "skip-verify"
	case "verify":
		if opts.TLSCAFile == "" {
			mysqlCfg.TLSConfig = "true"
			break
		}
		certificate, err := os.ReadFile(opts.TLSCAFile)
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
			ServerName: opts.Host,
		}); err != nil {
			return mysql.Config{}, fmt.Errorf("register MySQL TLS config: %w", err)
		}
		mysqlCfg.TLSConfig = name
	default:
		return mysql.Config{}, fmt.Errorf("unsupported MySQL TLS mode %q", opts.TLSMode)
	}

	return mysqlCfg, nil
}

package database

import (
	"os"
	"strings"
	"testing"
)

// File này kiểm chứng hành vi mysql config và các trường hợp lỗi liên quan.

// TestNewMySQLConfigSupportsIPv6AndTLSModes kiểm chứng kịch bản NewMySQLConfigSupportsIPv6AndTLSModes.
func TestNewMySQLConfigSupportsIPv6AndTLSModes(t *testing.T) {
	base := MySQLOptions{
		Host:     "2001:db8::1",
		Port:     "3306",
		Name:     "uam",
		User:     "uam",
		Password: "secret",
	}

	disabled, err := newMySQLConfig(base, false)
	if err != nil {
		t.Fatalf("newMySQLConfig(disable): %v", err)
	}
	if disabled.Addr != "[2001:db8::1]:3306" || disabled.TLSConfig != "" {
		t.Fatalf("disabled config = %+v", disabled)
	}

	base.TLSMode = "verify"
	verified, err := newMySQLConfig(base, true)
	if err != nil {
		t.Fatalf("newMySQLConfig(verify): %v", err)
	}
	if verified.TLSConfig != "true" || !verified.MultiStatements {
		t.Fatalf("verified config = %+v", verified)
	}

	base.TLSMode = "skip-verify"
	insecure, err := newMySQLConfig(base, false)
	if err != nil {
		t.Fatalf("newMySQLConfig(skip-verify): %v", err)
	}
	if insecure.TLSConfig != "skip-verify" {
		t.Fatalf("skip-verify TLS config = %q", insecure.TLSConfig)
	}
}

// TestNewMySQLConfigRejectsInvalidCA kiểm chứng kịch bản NewMySQLConfigRejectsInvalidCA.
func TestNewMySQLConfigRejectsInvalidCA(t *testing.T) {
	caFile := t.TempDir() + "/invalid-ca.pem"
	if err := os.WriteFile(caFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write CA fixture: %v", err)
	}
	_, err := newMySQLConfig(MySQLOptions{
		Host:      "db.example.test",
		Port:      "3306",
		TLSMode:   "verify",
		TLSCAFile: caFile,
	}, false)
	if err == nil || !strings.Contains(err.Error(), "valid PEM") {
		t.Fatalf("newMySQLConfig() error = %v", err)
	}
}

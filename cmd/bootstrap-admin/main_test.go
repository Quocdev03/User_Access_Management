package main

import (
	"strings"
	"testing"
)

// File này kiểm chứng hành vi main và các trường hợp lỗi liên quan.

// TestRejectKnownBootstrapPassword kiểm chứng kịch bản rejectKnownBootstrapPassword.
func TestRejectKnownBootstrapPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "retired password",
			password: "AdminPassword123!@#",
			wantErr:  true,
		},
		{
			name:     "allowed password",
			password: "TestOnly@Secure123",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rejectKnownBootstrapPassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Fatalf("rejectKnownBootstrapPassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParseAndValidateBootstrapInput kiểm chứng kịch bản ParseAndValidateBootstrapInput.
func TestParseAndValidateBootstrapInput(t *testing.T) {
	validArgs := []string{
		"--username", "first_admin",
		"--email", "admin@example.com",
		"--full-name", "First Administrator",
		"--phone", "0900000000",
		"--date-of-birth", "1990-01-01",
	}

	tests := []struct {
		name     string
		args     []string
		password string
		wantErr  bool
	}{
		{
			name:     "valid input",
			args:     validArgs,
			password: "Different@Secure123",
			wantErr:  false,
		},
		{
			name:     "missing environment password",
			args:     validArgs,
			password: "",
			wantErr:  true,
		},
		{
			name:     "weak environment password",
			args:     validArgs,
			password: "weak",
			wantErr:  true,
		},
		{
			name: "password flag is rejected",
			args: append(append([]string{}, validArgs...),
				"--password", "Different@Secure123"),
			password: "Different@Secure123",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := parseBootstrapInput(tt.args, func(key string) string {
				if key != bootstrapPasswordEnvName {
					t.Fatalf("unexpected environment key %q", key)
				}
				return tt.password
			})
			if err == nil {
				err = validateBootstrapInput(input)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("parse/validate error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), tt.password) && tt.password != "" {
				t.Fatal("validation error exposed the password")
			}
		})
	}
}

package access

import (
	"errors"
	"testing"
	"time"

	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này kiểm chứng các helper và logic phân quyền của access module.

// TestIsReservedRoleName kiểm chứng danh sách role bảo lưu của hệ thống.
func TestIsReservedRoleName(t *testing.T) {
	tests := []struct {
		name     string
		roleName string
		expected bool
	}{
		{name: "admin", roleName: RoleAdmin, expected: true},
		{name: "moderator", roleName: RoleModerator, expected: true},
		{name: "user", roleName: RoleUser, expected: true},
		{name: "custom_role", roleName: "editor", expected: false},
		{name: "empty", roleName: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isReservedRoleName(tt.roleName); got != tt.expected {
				t.Fatalf("isReservedRoleName(%q) = %v, want %v", tt.roleName, got, tt.expected)
			}
		})
	}
}

// TestErrorsIsConflict kiểm chứng việc nhận diện lỗi ErrConflict.
func TestErrorsIsConflict(t *testing.T) {
	conflictErr := apperror.ErrConflict.WithMessage("Hệ thống đã có quản trị viên")
	if !errorsIsConflict(conflictErr) {
		t.Fatal("expected errorsIsConflict to return true for conflict error")
	}

	genericErr := errors.New("database connection failed")
	if errorsIsConflict(genericErr) {
		t.Fatal("expected errorsIsConflict to return false for generic error")
	}

	notFoundErr := apperror.ErrNotFound
	if errorsIsConflict(notFoundErr) {
		t.Fatal("expected errorsIsConflict to return false for not found error")
	}
}

// TestUserFromRowPreservesEmptyRoles kiểm chứng việc giữ nguyên roles rỗng mà không gán mặc định user.
func TestUserFromRowPreservesEmptyRoles(t *testing.T) {
	u := &Users{}
	row := mysqlstore.AccessUser{
		ID:            10,
		Username:      "noroles",
		Email:         "noroles@example.com",
		FullName:      "No Roles User",
		Phone:         "0900000000",
		Status:        "active",
		EmailVerified: true,
		CreatedAt:     time.Now().UTC(),
	}

	emptyRoles := []string{}
	user := u.userFromRow(row, emptyRoles)
	if len(user.Roles) != 0 {
		t.Fatalf("expected 0 roles, got %d: %v", len(user.Roles), user.Roles)
	}
	if user.Roles == nil {
		t.Fatal("expected non-nil empty slice for roles")
	}
}

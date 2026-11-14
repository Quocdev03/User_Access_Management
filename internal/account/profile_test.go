package account

import (
	"testing"
	"time"
)

// File này kiểm chứng các helper và cấu trúc dữ liệu của profile module.

// TestProfileViewEmptyRoles kiểm chứng ProfileView giữ nguyên danh sách roles rỗng khi người dùng chưa được gán role.
func TestProfileViewEmptyRoles(t *testing.T) {
	roles := []string{}
	view := ProfileView{
		ID:            1,
		Username:      "testuser",
		Email:         "test@example.com",
		FullName:      "Test User",
		Phone:         "0900000000",
		Status:        "active",
		DateOfBirth:   "2000-01-01",
		EmailVerified: true,
		CreatedAt:     time.Now().UTC(),
		Roles:         roles,
	}

	if len(view.Roles) != 0 {
		t.Fatalf("expected 0 roles, got %d: %v", len(view.Roles), view.Roles)
	}
	if view.Roles == nil {
		t.Fatal("expected non-nil empty slice for roles")
	}
}

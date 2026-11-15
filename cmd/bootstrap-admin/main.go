// Package main cung cấp lệnh khởi tạo quản trị viên đầu tiên bằng thao tác vận hành tường minh.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	accessapp "github.com/quocdev03/user-access-management/internal/access"
	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/database"
	"github.com/quocdev03/user-access-management/pkg/hash"
	"golang.org/x/crypto/bcrypt"
)

// File này kiểm tra input vận hành và tạo quản trị viên đầu tiên trong transaction.

const (
	// bootstrapPasswordEnvName là tên biến môi trường chứa password khởi tạo admin.
	//nolint:gosec // #nosec G101 -- environment variable key name only, not credentials
	bootstrapPasswordEnvName = "UAM_BOOTSTRAP_ADMIN_PASSWORD" // #nosec G101

	// retiredBootstrapCredentialHash là bcrypt hash của credential bootstrap mặc định cũ nhằm từ chối tái sử dụng.
	//nolint:gosec // #nosec G101 -- bcrypt hash blacklist for retired credentials
	retiredBootstrapCredentialHash = "$2a$10$MrX03IY.gdR12cHu7G/ODOKOg8PindR.1lNBEDlVy5FROp/TjZLvy" // #nosec G101
)

// bootstrapInput chứa các trường dữ liệu đầu vào bắt buộc để khởi tạo tài khoản quản trị viên đầu tiên.
type bootstrapInput struct {
	Username    string `validate:"required,min=3,max=50"`
	Email       string `validate:"required,email,max=255"`
	Password    string `validate:"required"`
	FullName    string `validate:"required,max=100"`
	Phone       string `validate:"required,max=20"`
	DateOfBirth string `validate:"required,datetime=2006-01-02"`
}

// parseBootstrapInput đọc flag và password từ environment mà không đưa secret vào argv.
func parseBootstrapInput(args []string, getenv func(string) string) (bootstrapInput, error) {
	var input bootstrapInput

	flags := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&input.Username, "username", "", "administrator username")
	flags.StringVar(&input.Email, "email", "", "administrator email")
	flags.StringVar(&input.FullName, "full-name", "", "administrator full name")
	flags.StringVar(&input.Phone, "phone", "", "administrator phone")
	flags.StringVar(&input.DateOfBirth, "date-of-birth", "", "administrator birth date (YYYY-MM-DD)")

	if err := flags.Parse(args); err != nil {
		return bootstrapInput{}, fmt.Errorf("parse bootstrap arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return bootstrapInput{}, errors.New("bootstrap-admin does not accept positional arguments")
	}

	input.Username = strings.TrimSpace(input.Username)
	input.Email = strings.TrimSpace(input.Email)
	input.FullName = strings.TrimSpace(input.FullName)
	input.Phone = strings.TrimSpace(input.Phone)
	input.DateOfBirth = strings.TrimSpace(input.DateOfBirth)
	input.Password = getenv(bootstrapPasswordEnvName)

	return input, nil
}

// rejectKnownBootstrapPassword chặn password trùng credential bootstrap mặc định từng bị phát hành.
func rejectKnownBootstrapPassword(rawPassword string) error {
	if bcrypt.CompareHashAndPassword([]byte(retiredBootstrapCredentialHash), []byte(rawPassword)) == nil {
		return errors.New("bootstrap password is a retired known credential")
	}
	return nil
}

// validateBootstrapInput từ chối dữ liệu quản trị viên sai định dạng trước khi mở transaction.
func validateBootstrapInput(input bootstrapInput) error {
	if err := validator.New().Struct(input); err != nil {
		return fmt.Errorf("validate bootstrap input: %w", err)
	}
	if err := rejectKnownBootstrapPassword(input.Password); err != nil {
		return err
	}
	if err := hash.ValidateNewPassword(input.Password); err != nil {
		return fmt.Errorf("validate bootstrap password: %w", err)
	}
	return nil
}

// run thực thi bootstrap transaction và trả lỗi thay vì kết thúc process trực tiếp.
func run(ctx context.Context, args []string, getenv func(string) string) error {
	input, err := parseBootstrapInput(args, getenv)
	if err != nil {
		return err
	}
	if err := validateBootstrapInput(input); err != nil {
		return err
	}

	dateOfBirth, err := time.Parse("2006-01-02", input.DateOfBirth)
	if err != nil {
		return fmt.Errorf("parse date of birth: %w", err)
	}
	passwordHash, err := hash.HashPassword(input.Password)
	if err != nil {
		return fmt.Errorf("hash bootstrap password: %w", err)
	}

	cfg, err := config.Load(".")
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	db, err := database.ConnectMySQL(cfg.Database.MySQLOptions())
	if err != nil {
		return fmt.Errorf("connect MySQL: %w", err)
	}
	defer db.Close()

	bootstrap := accessapp.NewBootstrap(
		db,
		mysqlstore.NewAccountStore(db),
		mysqlstore.NewProfileStore(db),
		mysqlstore.NewAccessStore(db),
		mysqlstore.NewAuditStore(db),
	)
	account := &accessapp.BootstrapAccount{
		Username:     input.Username,
		Email:        input.Email,
		PasswordHash: passwordHash,
		FullName:     input.FullName,
		Phone:        input.Phone,
		DateOfBirth:  dateOfBirth,
	}
	if err := bootstrap.Create(ctx, account); err != nil {
		return err
	}

	log.Printf(
		"bootstrap administrator created: user_id=%d username=%q",
		account.ID,
		account.Username,
	)
	return nil
}

// main đọc input vận hành, tạo quản trị viên đầu tiên và không nhận mật khẩu qua command line.
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := run(ctx, os.Args[1:], os.Getenv); err != nil {
		log.Fatal(err)
	}
}

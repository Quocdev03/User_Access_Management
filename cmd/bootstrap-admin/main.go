// Command bootstrap-admin creates the first administrator through an explicit
// one-off operator action. It never accepts the password on the command line.
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
)

const (
	bootstrapPasswordEnv         = "UAM_BOOTSTRAP_ADMIN_PASSWORD"
	knownBootstrapPasswordSHA256 = "ba8bcfb1dc44652223d3ed64fe68e18ba16ee7d43f1fda5668d0d03307e8b0fa"
)

type bootstrapInput struct {
	Username    string `validate:"required,min=3,max=50"`
	Email       string `validate:"required,email,max=255"`
	Password    string `validate:"required"`
	FullName    string `validate:"required,max=100"`
	Phone       string `validate:"required,max=20"`
	DateOfBirth string `validate:"required,datetime=2006-01-02"`
}

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
	input.Password = getenv(bootstrapPasswordEnv)

	return input, nil
}

func rejectKnownBootstrapPasswordHash(passwordHash string) error {
	if passwordHash == knownBootstrapPasswordSHA256 {
		return errors.New("bootstrap password is a retired known credential")
	}
	return nil
}

func validateBootstrapInput(input bootstrapInput) error {
	if err := validator.New().Struct(input); err != nil {
		return fmt.Errorf("validate bootstrap input: %w", err)
	}
	if err := rejectKnownBootstrapPasswordHash(hash.SHA256(input.Password)); err != nil {
		return err
	}
	if err := hash.ValidateNewPassword(input.Password); err != nil {
		return fmt.Errorf("validate bootstrap password: %w", err)
	}
	return nil
}

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
	db, err := database.ConnectMySQL(cfg.Database)
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

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := run(ctx, os.Args[1:], os.Getenv); err != nil {
		log.Fatal(err)
	}
}

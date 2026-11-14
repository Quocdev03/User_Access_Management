// Package main cung cấp lệnh áp dụng migration MySQL của UAM.
package main

import (
	"log"

	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/pkg/database"
)

// File này nạp cấu hình MySQL và áp dụng các migration chưa chạy.

// main kết nối MySQL và áp dụng migration trước khi kết thúc tiến trình.
func main() {
	cfg, err := config.Load(".")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if err := database.RunMigrations(
		cfg.Database.MySQLOptions(),
		"migrations",
		cfg.App.Env,
	); err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}
	log.Printf("Database migrations applied successfully")
}

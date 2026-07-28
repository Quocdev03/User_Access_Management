package main

import (
	"log"

	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/pkg/database"
)

func main() {
	cfg, err := config.Load(".")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if err := database.RunMigrations(
		cfg.Database,
		"migrations",
		cfg.App.Env,
	); err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}
	log.Printf("Database migrations applied successfully")
}

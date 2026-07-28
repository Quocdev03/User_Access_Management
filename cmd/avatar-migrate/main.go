package main

import (
	"context"
	"flag"
	"log"

	"github.com/quocdev03/user-access-management/internal/blob"
	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/internal/jobs"
	"github.com/quocdev03/user-access-management/pkg/database"
	"github.com/quocdev03/user-access-management/pkg/logger"
	"go.uber.org/zap"
)

func main() {
	batchSize := flag.Int("batch-size", 100, "profiles loaded per batch")
	flag.Parse()

	cfg, err := config.Load(".")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if cfg.Blob.Provider != "s3" {
		log.Fatal("BLOB_PROVIDER=s3 is required for avatar migration")
	}
	logr, err := logger.New(cfg.App.Env)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() { _ = logr.Sync() }()
	db, err := database.ConnectMySQL(cfg.Database)
	if err != nil {
		logr.Fatal("Failed to connect to MySQL", zap.Error(err))
	}
	defer db.Close()
	source, err := blob.NewLocalStore(cfg.Blob.LocalRoot)
	if err != nil {
		logr.Fatal("Failed to initialize local avatar source", zap.Error(err))
	}
	target, err := blob.NewS3Store(context.Background(), cfg.Blob)
	if err != nil {
		logr.Fatal("Failed to initialize S3 avatar target", zap.Error(err))
	}
	result, err := jobs.NewAvatarMigrator(
		db,
		source,
		target,
		logr,
	).Run(context.Background(), *batchSize)
	if err != nil {
		logr.Fatal("Avatar migration failed", zap.Error(err))
	}
	logr.Info(
		"Avatar migration completed",
		zap.Int("copied", result.Copied),
		zap.Int("skipped_external", result.Skipped),
	)
}

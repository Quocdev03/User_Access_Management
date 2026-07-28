package main

import (
	"context"
	"log"
	"os/signal"
	"sync"
	"syscall"

	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/internal/jobs"
	mailmessage "github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	"github.com/quocdev03/user-access-management/pkg/database"
	"github.com/quocdev03/user-access-management/pkg/logger"
	"go.uber.org/zap"
)

func main() {
	cfg, err := config.Load(".")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	logr, err := logger.New(cfg.App.Env)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() { _ = logr.Sync() }()
	zap.ReplaceGlobals(logr)

	db, err := database.ConnectMySQL(cfg.Database)
	if err != nil {
		logr.Fatal("Failed to connect to MySQL", zap.Error(err))
	}
	defer db.Close()
	redisClient, err := database.ConnectRedis(cfg.Redis)
	if err != nil {
		logr.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer redisClient.Close()
	codec, err := mailmessage.NewSecretCodec(cfg.Security.OTPPepper)
	if err != nil {
		logr.Fatal("Failed to initialize outbox codec", zap.Error(err))
	}

	outbox := jobs.NewOutboxWorker(
		db,
		mysqlstore.NewOutboxStore(db),
		codec,
		mailmessage.NewSender(cfg, logr),
		cfg.Outbox,
		logr,
	)
	cleanup := jobs.NewCleanupWorker(
		mysqlstore.NewVerificationChallengeStore(db),
		mysqlstore.NewSessionStore(db),
		mysqlstore.NewPasswordResetStore(db),
		mysqlstore.NewEmailChangeStore(db),
		mysqlstore.NewOutboxStore(db),
		mysqlstore.NewAuditStore(db),
		redisstore.NewLeaseStore(redisClient),
		cfg.Cleanup,
		logr,
	)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		outbox.Start(ctx)
	}()
	go func() {
		defer workers.Done()
		cleanup.Start(ctx)
	}()
	<-ctx.Done()
	logr.Info("Worker shutdown requested")
	workers.Wait()
	logr.Info("Worker stopped")
}

// Package main khởi động HTTP API và quản lý vòng đời các dependency của UAM.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/quocdev03/user-access-management/docs/openapi"
	"github.com/quocdev03/user-access-management/internal/blob"
	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/internal/httpapi"
	"github.com/quocdev03/user-access-management/pkg/database"
	"github.com/quocdev03/user-access-management/pkg/logger"
	"go.uber.org/zap"
)

// File này wire HTTP server với domain use case, store và lifecycle shutdown.

// main khởi tạo dependency, phục vụ HTTP và đóng tài nguyên theo tín hiệu hệ điều hành.
// @title User Access Management API
// @version 1.0
// @description Hệ thống quản lý truy cập người dùng RESTful API bằng Golang/Gin.
// @termsOfService http://swagger.io/terms/
// @contact.name Quoc Dev
// @contact.email quocdt2003@gmail.com
// @host localhost:8080
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
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

	logr.Info("Starting User Access Management Service...", zap.String("env", cfg.App.Env))

	db, err := database.ConnectMySQL(cfg.Database.MySQLOptions())
	if err != nil {
		logr.Fatal("Failed to connect to MySQL", zap.Error(err))
	}
	defer db.Close()
	logr.Info("Connected to MySQL successfully")

	redisClient, err := database.ConnectRedis(cfg.Redis.RedisOptions())
	if err != nil {
		logr.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer redisClient.Close()
	logr.Info("Connected to Redis successfully")

	blobStore, err := blob.NewStore(context.Background(), cfg.Blob)
	if err != nil {
		logr.Fatal("Failed to initialize blob store", zap.Error(err))
	}

	if cfg.App.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := httpapi.Setup(db, redisClient, logr, cfg, blobStore)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", cfg.App.Port),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	go func() {
		logr.Info("Server listening", zap.String("port", cfg.App.Port), zap.String("url", fmt.Sprintf("http://localhost:%s", cfg.App.Port)))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logr.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logr.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logr.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logr.Info("Server exiting")
}

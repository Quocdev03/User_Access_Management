package database

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/redis/go-redis/v9"
)

func ConnectRedis(cfg config.RedisConfig) (*redis.Client, error) {
	var opt *redis.Options
	var err error

	if strings.HasPrefix(cfg.Host, "redis://") || strings.HasPrefix(cfg.Host, "rediss://") {
		opt, err = redis.ParseURL(cfg.Host)
		if err != nil {
			return nil, fmt.Errorf("failed to parse redis URL: %w", err)
		}
	} else {
		opt = &redis.Options{
			Addr:     net.JoinHostPort(cfg.Host, cfg.Port),
			Password: cfg.Password,
			DB:       0,
		}
	}
	opt.PoolSize = cfg.PoolSize
	opt.MinIdleConns = cfg.MinIdleConns

	client := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		closeErr := client.Close()
		if closeErr != nil {
			return nil, errors.Join(
				fmt.Errorf("failed to connect to Redis: %w", err),
				fmt.Errorf("close failed Redis client: %w", closeErr),
			)
		}
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	return client, nil
}

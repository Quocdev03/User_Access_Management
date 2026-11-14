package database

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// File này mở Redis client và xác minh kết nối khi khởi động.

// ConnectRedis mở client và ping Redis để startup thất bại sớm khi cấu hình sai.
func ConnectRedis(opts RedisOptions) (*redis.Client, error) {
	var opt *redis.Options
	var err error

	if strings.HasPrefix(opts.Host, "redis://") || strings.HasPrefix(opts.Host, "rediss://") {
		opt, err = redis.ParseURL(opts.Host)
		if err != nil {
			return nil, fmt.Errorf("failed to parse redis URL: %w", err)
		}
	} else {
		opt = &redis.Options{
			Addr:     net.JoinHostPort(opts.Host, opts.Port),
			Password: opts.Password,
			DB:       0,
		}
	}
	opt.PoolSize = opts.PoolSize
	opt.MinIdleConns = opts.MinIdleConns

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

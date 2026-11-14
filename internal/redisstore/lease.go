// Package redisstore lưu TTL state và thực hiện các thao tác Redis nguyên tử.
package redisstore

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// File này acquire và release distributed lease bằng token ownership.

var releaseLease = redis.NewScript(`
	if redis.call("GET", KEYS[1]) == ARGV[1] then
		return redis.call("DEL", KEYS[1])
	end
	return 0
`)

// LeaseStore quản lý việc cấp phát và giải phóng distributed lease trên Redis cho worker.
type LeaseStore struct {
	client *redis.Client
}

const leaseKeyPrefix = "uam:v1:worker-lease:"

// NewLeaseStore khởi tạo LeaseStore với các dependency được cung cấp.
func NewLeaseStore(client *redis.Client) *LeaseStore {
	return &LeaseStore{client: client}
}

// Acquire giành lease bằng ownership token và TTL trong một thao tác Redis nguyên tử.
func (s *LeaseStore) Acquire(
	ctx context.Context,
	name string,
	ttl time.Duration,
) (string, bool, error) {
	if ttl < time.Second {
		return "", false, fmt.Errorf("lease TTL must be at least one second")
	}
	token := uuid.NewString()
	acquired, err := s.client.SetNX(ctx, leaseKeyPrefix+name, token, ttl).Result()
	if err != nil {
		return "", false, fmt.Errorf("acquire Redis lease: %w", err)
	}
	return token, acquired, nil
}

// Release chỉ xóa lease khi ownership token vẫn khớp.
func (s *LeaseStore) Release(ctx context.Context, name, token string) error {
	if token == "" {
		return nil
	}
	if err := releaseLease.Run(
		ctx,
		s.client,
		[]string{leaseKeyPrefix + name},
		token,
	).Err(); err != nil && err != redis.Nil {
		return fmt.Errorf("release Redis lease: %w", err)
	}
	return nil
}

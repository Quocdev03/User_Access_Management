//go:build integration

package redisstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestLeaseOwnershipAndRelease(t *testing.T) {
	address := os.Getenv("UAM_REDIS_TEST_ADDR")
	if address == "" {
		t.Skip("UAM_REDIS_TEST_ADDR is not configured")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	if err := client.Del(ctx, "uam:v1:worker-lease:integration-test").Err(); err != nil {
		t.Fatalf("clear test lease: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Del(ctx, "uam:v1:worker-lease:integration-test").Err()
	})
	first := NewLeaseStore(client)
	second := NewLeaseStore(client)

	token, acquired, err := first.Acquire(ctx, "integration-test", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("first Acquire() = token %q, acquired %v, err %v", token, acquired, err)
	}
	if _, acquired, err := second.Acquire(ctx, "integration-test", time.Minute); err != nil || acquired {
		t.Fatalf("second Acquire() acquired %v, err %v", acquired, err)
	}
	if err := second.Release(ctx, "integration-test", "wrong-owner"); err != nil {
		t.Fatalf("wrong-owner Release(): %v", err)
	}
	if _, acquired, err := second.Acquire(ctx, "integration-test", time.Minute); err != nil || acquired {
		t.Fatalf("lease released by wrong owner: acquired %v, err %v", acquired, err)
	}
	if err := first.Release(ctx, "integration-test", token); err != nil {
		t.Fatalf("owner Release(): %v", err)
	}
	if token, acquired, err := second.Acquire(ctx, "integration-test", time.Minute); err != nil || !acquired {
		t.Fatalf("Acquire after release = token %q, acquired %v, err %v", token, acquired, err)
	}
}

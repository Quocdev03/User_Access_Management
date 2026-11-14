//go:build integration

package redisstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// File này kiểm chứng tích hợp limiter integration với các dependency runtime liên quan.

// TestLimiterTokenBucketAndBanAreAtomic kiểm chứng kịch bản LimiterTokenBucketAndBanAreAtomic.
func TestLimiterTokenBucketAndBanAreAtomic(t *testing.T) {
	address := os.Getenv("UAM_REDIS_TEST_ADDR")
	if address == "" {
		t.Skip("UAM_REDIS_TEST_ADDR is not configured")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	subject := "limiter-integration-" + time.Now().Format("150405.000000000")
	ctx := context.Background()
	keys := []string{
		"uam:v1:security:{" + subject + "}:ban",
		"uam:v1:security:{" + subject + "}:bucket:test",
		"uam:v1:security:{" + subject + "}:violations:test",
	}
	t.Cleanup(func() { _ = client.Del(ctx, keys...).Err() })

	limiter := NewLimiter(client)
	policy := LimitPolicy{
		Capacity:    2,
		AbuseLimit:  2,
		Window:      time.Minute,
		BanDuration: time.Minute,
	}
	for i := 0; i < 2; i++ {
		decision, _, err := limiter.Allow(ctx, "test", subject, policy)
		if err != nil || decision != LimitAllowed {
			t.Fatalf("allow %d: decision=%d err=%v", i, decision, err)
		}
	}
	decision, retry, err := limiter.Allow(ctx, "test", subject, policy)
	if err != nil || decision != LimitRejected || retry <= 0 {
		t.Fatalf("reject: decision=%d retry=%s err=%v", decision, retry, err)
	}
	decision, _, err = limiter.Allow(ctx, "test", subject, policy)
	if err != nil || decision != LimitBanned {
		t.Fatalf("ban: decision=%d err=%v", decision, err)
	}
	if exists, err := client.Exists(ctx, keys[0]).Result(); err != nil || exists != 1 {
		t.Fatalf("ban key exists=%d err=%v", exists, err)
	}
}

package redisstore

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// File này lưu JTI blacklist và refresh-reuse marker có TTL trong Redis.

// TokenStore quản lý blacklist JTI của access token và marker phát hiện reuse refresh token trong Redis.
type TokenStore struct {
	client *redis.Client
}

// NewTokenStore khởi tạo TokenStore với các dependency được cung cấp.
func NewTokenStore(client *redis.Client) *TokenStore {
	return &TokenStore{client: client}
}

// BlacklistJTI lưu access JTI đến hết TTL còn lại của token.
func (s *TokenStore) BlacklistJTI(ctx context.Context, jti string, ttl time.Duration) error {
	return s.client.Set(ctx, "uam:v1:jti:"+jti, "1", ttl).Err()
}

// IsJTIBlacklisted kiểm tra JTI marker và trả nguyên lỗi Redis để caller fail closed.
func (s *TokenStore) IsJTIBlacklisted(ctx context.Context, jti string) (bool, error) {
	count, err := s.client.Exists(ctx, "uam:v1:jti:"+jti).Result()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// MarkRefreshReuse lưu refresh-reuse marker đến khi token hết hiệu lực.
func (s *TokenStore) MarkRefreshReuse(ctx context.Context, tokenHash string, ttl time.Duration) error {
	return s.client.Set(ctx, "uam:v1:refresh-reuse:"+tokenHash, "1", ttl).Err()
}

// IsRefreshReuseMarked kiểm tra reuse marker và trả nguyên lỗi Redis để caller fail closed.
func (s *TokenStore) IsRefreshReuseMarked(ctx context.Context, tokenHash string) (bool, error) {
	count, err := s.client.Exists(
		ctx,
		"uam:v1:refresh-reuse:"+tokenHash,
	).Result()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

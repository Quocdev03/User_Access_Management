package redisstore

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type TokenStore struct {
	client *redis.Client
}

func NewTokenStore(client *redis.Client) *TokenStore {
	return &TokenStore{client: client}
}

func (s *TokenStore) BlacklistJTI(ctx context.Context, jti string, ttl time.Duration) error {
	return s.client.Set(ctx, "uam:v1:jti:"+jti, "1", ttl).Err()
}

func (s *TokenStore) IsJTIBlacklisted(ctx context.Context, jti string) (bool, error) {
	count, err := s.client.Exists(ctx, "uam:v1:jti:"+jti).Result()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *TokenStore) MarkRefreshReuse(ctx context.Context, tokenHash string, ttl time.Duration) error {
	return s.client.Set(ctx, "uam:v1:refresh-reuse:"+tokenHash, "1", ttl).Err()
}

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

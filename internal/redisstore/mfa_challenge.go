package redisstore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// File này lưu và consume MFA login challenge có TTL trong Redis.

// MFAChallenge chứa thông tin định danh người dùng và auth_version gắn với thử thách MFA login.
type MFAChallenge struct {
	UserID      uint64
	AuthVersion uint64
}

// MFAChallengeClaim chứa kết quả claim thử thách MFA kèm số lần thử và TTL còn lại.
type MFAChallengeClaim struct {
	Challenge    MFAChallenge
	ClaimToken   string
	Attempts     int
	RemainingTTL time.Duration
}

// MFAChallengeStore quản lý việc tạo, claim và hoàn tất các thử thách MFA login tạm thời trên Redis.
type MFAChallengeStore struct {
	client        *redis.Client
	createScript  *redis.Script
	claimScript   *redis.Script
	finishScript  *redis.Script
	releaseScript *redis.Script
}

// NewMFAChallengeStore khởi tạo MFAChallengeStore với các dependency được cung cấp.
func NewMFAChallengeStore(client *redis.Client) *MFAChallengeStore {
	return &MFAChallengeStore{
		client: client,
		createScript: redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 1 then
	return 0
end
redis.call("HSET", KEYS[1],
	"state", "ready",
	"user_id", ARGV[1],
	"auth_version", ARGV[2],
	"attempts", 0)
redis.call("PEXPIRE", KEYS[1], ARGV[3])
return 1
`),
		claimScript: redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 0 then
	return {0}
end
if redis.call("HGET", KEYS[1], "state") ~= "ready" then
	return {2}
end
local attempts = tonumber(redis.call("HGET", KEYS[1], "attempts"))
if attempts == nil or attempts >= tonumber(ARGV[2]) then
	redis.call("DEL", KEYS[1])
	return {3}
end
local user_id = redis.call("HGET", KEYS[1], "user_id")
local auth_version = redis.call("HGET", KEYS[1], "auth_version")
if user_id == false or auth_version == false then
	redis.call("DEL", KEYS[1])
	return {4}
end
redis.call("HSET", KEYS[1], "state", "claimed", "claim_token", ARGV[1])
return {1, user_id, auth_version, attempts, redis.call("PTTL", KEYS[1])}
`),
		finishScript: redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 0 then
	return 0
end
if redis.call("HGET", KEYS[1], "state") ~= "claimed"
	or redis.call("HGET", KEYS[1], "claim_token") ~= ARGV[1] then
	return 2
end
if ARGV[2] == "1" then
	redis.call("DEL", KEYS[1])
	return 1
end
local attempts = redis.call("HINCRBY", KEYS[1], "attempts", 1)
if attempts >= tonumber(ARGV[3]) then
	redis.call("DEL", KEYS[1])
	return 3
end
redis.call("HSET", KEYS[1], "state", "ready")
redis.call("HDEL", KEYS[1], "claim_token")
return 4
`),
		releaseScript: redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 0 then
	return 0
end
if redis.call("HGET", KEYS[1], "state") ~= "claimed"
	or redis.call("HGET", KEYS[1], "claim_token") ~= ARGV[1] then
	return 2
end
redis.call("HSET", KEYS[1], "state", "ready")
redis.call("HDEL", KEYS[1], "claim_token")
return 1
`),
	}
}

// Create lưu MFA login challenge có TTL để tách bước password và TOTP.
func (s *MFAChallengeStore) Create(
	ctx context.Context,
	challenge MFAChallenge,
	ttl time.Duration,
) (string, error) {
	if s == nil || s.client == nil {
		return "", fmt.Errorf("MFA challenge store is not configured")
	}
	if challenge.UserID == 0 || ttl < time.Second {
		return "", fmt.Errorf("invalid MFA challenge")
	}
	for range 3 {
		token, err := randomOpaqueToken(32)
		if err != nil {
			return "", err
		}
		created, err := s.createScript.Run(
			ctx,
			s.client,
			[]string{mfaChallengeKey(token)},
			challenge.UserID,
			challenge.AuthVersion,
			ttl.Milliseconds(),
		).Int()
		if err != nil {
			return "", fmt.Errorf("create MFA challenge: %w", err)
		}
		if created == 1 {
			return token, nil
		}
	}
	return "", fmt.Errorf("create unique MFA challenge")
}

// Claim khóa tạm challenge cho một lần xác minh và trả snapshot bất biến cho use case.
func (s *MFAChallengeStore) Claim(
	ctx context.Context,
	token string,
	maxAttempts int,
) (MFAChallengeClaim, bool, error) {
	if s == nil || s.client == nil {
		return MFAChallengeClaim{}, false, fmt.Errorf(
			"MFA challenge store is not configured",
		)
	}
	if token == "" || maxAttempts < 1 {
		return MFAChallengeClaim{}, false, fmt.Errorf("invalid MFA challenge claim")
	}
	claimToken, err := randomOpaqueToken(24)
	if err != nil {
		return MFAChallengeClaim{}, false, err
	}
	result, err := s.claimScript.Run(
		ctx,
		s.client,
		[]string{mfaChallengeKey(token)},
		claimToken,
		maxAttempts,
	).Slice()
	if err != nil {
		return MFAChallengeClaim{}, false, fmt.Errorf("claim MFA challenge: %w", err)
	}
	if len(result) == 0 {
		return MFAChallengeClaim{}, false, fmt.Errorf("empty MFA challenge claim result")
	}
	state, ok := result[0].(int64)
	if !ok {
		return MFAChallengeClaim{}, false, fmt.Errorf(
			"unexpected MFA challenge state %T",
			result[0],
		)
	}
	if state != 1 {
		if state == 4 {
			return MFAChallengeClaim{}, false, fmt.Errorf(
				"corrupt MFA challenge payload",
			)
		}
		return MFAChallengeClaim{}, false, nil
	}
	if len(result) != 5 {
		return MFAChallengeClaim{}, false, fmt.Errorf(
			"unexpected MFA challenge result length %d",
			len(result),
		)
	}
	userID, err := parseRedisUint(result[1], "user id")
	if err != nil {
		return MFAChallengeClaim{}, false, err
	}
	authVersion, err := parseRedisUint(result[2], "auth version")
	if err != nil {
		return MFAChallengeClaim{}, false, err
	}
	attempts, err := parseRedisUint(result[3], "attempts")
	if err != nil {
		return MFAChallengeClaim{}, false, err
	}
	remainingMilliseconds, err := parseRedisUint(result[4], "remaining TTL")
	if err != nil {
		return MFAChallengeClaim{}, false, err
	}
	return MFAChallengeClaim{
		Challenge: MFAChallenge{
			UserID:      userID,
			AuthVersion: authVersion,
		},
		ClaimToken:   claimToken,
		Attempts:     int(attempts),
		RemainingTTL: time.Duration(remainingMilliseconds) * time.Millisecond,
	}, true, nil
}

// Finish consume challenge đã claim khi MFA login hoàn tất thành công.
func (s *MFAChallengeStore) Finish(
	ctx context.Context,
	token string,
	claimToken string,
	valid bool,
	maxAttempts int,
) (bool, error) {
	validArgument := "0"
	if valid {
		validArgument = "1"
	}
	state, err := s.finishScript.Run(
		ctx,
		s.client,
		[]string{mfaChallengeKey(token)},
		claimToken,
		validArgument,
		maxAttempts,
	).Int()
	if err != nil {
		return false, fmt.Errorf("finish MFA challenge: %w", err)
	}
	switch state {
	case 1:
		return true, nil
	case 3, 4:
		return false, nil
	case 0, 2:
		return false, fmt.Errorf("MFA challenge claim is no longer owned")
	default:
		return false, fmt.Errorf("unexpected MFA challenge finish state %d", state)
	}
}

// Release trả challenge đang claim về trạng thái có thể thử lại khi use case thất bại.
func (s *MFAChallengeStore) Release(
	ctx context.Context,
	token string,
	claimToken string,
) error {
	state, err := s.releaseScript.Run(
		ctx,
		s.client,
		[]string{mfaChallengeKey(token)},
		claimToken,
	).Int()
	if err != nil {
		return fmt.Errorf("release MFA challenge: %w", err)
	}
	if state != 1 {
		return fmt.Errorf("MFA challenge claim is no longer owned")
	}
	return nil
}

// mfaChallengeKey namespace challenge token để không va chạm Redis key khác.
func mfaChallengeKey(token string) string {
	return "uam:v1:mfa:{" + token + "}"
}

// randomOpaqueToken tạo challenge token đủ entropy và không chứa business state.
func randomOpaqueToken(size int) (string, error) {
	random := make([]byte, size)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate secure random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

// parseRedisUint từ chối Redis integer field bị thiếu, âm hoặc sai định dạng.
func parseRedisUint(value any, name string) (uint64, error) {
	switch typed := value.(type) {
	case int64:
		if typed < 0 {
			return 0, fmt.Errorf("MFA %s is negative", name)
		}
		return uint64(typed), nil
	case string:
		parsed, err := strconv.ParseUint(typed, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse MFA %s: %w", name, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("unexpected MFA %s type %T", name, value)
	}
}

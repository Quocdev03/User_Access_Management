package redisstore

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// File này thực hiện token bucket, violation và temporary ban bằng Redis Lua.

// LimitDecision biểu diễn quyết định cho phép, từ chối hoặc cấm tạm thời của rate limiter.
type LimitDecision uint8

const (
	LimitAllowed LimitDecision = iota
	LimitRejected
	LimitBanned
)

// LimitPolicy quy định dung lượng token bucket, ngưỡng vi phạm lạm dụng và thời gian ban.
type LimitPolicy struct {
	Capacity    int
	AbuseLimit  int
	Window      time.Duration
	BanDuration time.Duration
}

// Limiter triển khai thuật toán rate limiting token bucket có hỗ trợ tạm cấm IP bằng Redis Lua script.
type Limiter struct {
	client *redis.Client
	script *redis.Script
}

// NewLimiter khởi tạo Limiter với các dependency được cung cấp.
func NewLimiter(client *redis.Client) *Limiter {
	return &Limiter{
		client: client,
		script: redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 1 then
	return {2, math.max(0, redis.call("PTTL", KEYS[1]))}
end

local now = redis.call("TIME")
local now_ms = (now[1] * 1000) + math.floor(now[2] / 1000)
local capacity = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local abuse_limit = tonumber(ARGV[3])
local ban_ms = tonumber(ARGV[4])
local bucket_ttl = window_ms * 2

local bucket = redis.call("HMGET", KEYS[2], "tokens", "updated")
local tokens = tonumber(bucket[1])
local updated = tonumber(bucket[2])
if tokens == nil or updated == nil then
	tokens = capacity
	updated = now_ms
else
	local elapsed = math.max(0, now_ms - updated)
	tokens = math.min(capacity, tokens + (elapsed * capacity / window_ms))
	updated = now_ms
end

if tokens >= 1 then
	tokens = tokens - 1
	redis.call("HSET", KEYS[2], "tokens", tokens, "updated", updated)
	redis.call("PEXPIRE", KEYS[2], bucket_ttl)
	return {0, 0}
end

redis.call("HSET", KEYS[2], "tokens", tokens, "updated", updated)
redis.call("PEXPIRE", KEYS[2], bucket_ttl)
local violations = redis.call("INCR", KEYS[3])
if violations == 1 then
	redis.call("PEXPIRE", KEYS[3], window_ms)
end
if violations >= abuse_limit then
	redis.call("SET", KEYS[1], "1", "PX", ban_ms)
	redis.call("DEL", KEYS[3])
	return {2, ban_ms}
end

local retry_ms = math.ceil((1 - tokens) * window_ms / capacity)
return {1, retry_ms}
`),
	}
}

// Allow quyết định token-bucket, violation và temporary ban trong một Redis Lua operation.
func (l *Limiter) Allow(
	ctx context.Context,
	scope string,
	subject string,
	policy LimitPolicy,
) (LimitDecision, time.Duration, error) {
	if l == nil || l.client == nil {
		return LimitRejected, 0, fmt.Errorf("rate limiter is not configured")
	}
	if scope == "" || subject == "" {
		return LimitRejected, 0, fmt.Errorf("rate limiter scope and subject are required")
	}
	if policy.Capacity < 1 ||
		policy.AbuseLimit < 1 ||
		policy.Window < time.Second ||
		policy.BanDuration < time.Second {
		return LimitRejected, 0, fmt.Errorf("invalid rate limiter policy")
	}

	tag := "{" + subject + "}"
	keys := []string{
		"uam:v1:security:" + tag + ":ban",
		"uam:v1:security:" + tag + ":bucket:" + scope,
		"uam:v1:security:" + tag + ":violations:" + scope,
	}
	result, err := l.script.Run(
		ctx,
		l.client,
		keys,
		policy.Capacity,
		policy.Window.Milliseconds(),
		policy.AbuseLimit,
		policy.BanDuration.Milliseconds(),
	).Slice()
	if err != nil {
		return LimitRejected, 0, fmt.Errorf("run rate limiter script: %w", err)
	}
	if len(result) != 2 {
		return LimitRejected, 0, fmt.Errorf("unexpected rate limiter result length %d", len(result))
	}

	state, ok := result[0].(int64)
	if !ok {
		return LimitRejected, 0, fmt.Errorf("unexpected rate limiter state %T", result[0])
	}
	retryMilliseconds, ok := result[1].(int64)
	if !ok {
		return LimitRejected, 0, fmt.Errorf("unexpected rate limiter retry value %T", result[1])
	}

	var decision LimitDecision
	switch state {
	case int64(LimitAllowed):
		decision = LimitAllowed
	case int64(LimitRejected):
		decision = LimitRejected
	case int64(LimitBanned):
		decision = LimitBanned
	default:
		return LimitRejected, 0, fmt.Errorf("unexpected rate limiter state %d", state)
	}

	return decision, time.Duration(retryMilliseconds) * time.Millisecond, nil
}

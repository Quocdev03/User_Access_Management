package session

import (
	"context"
	"time"
)

// TokenState is the Redis TTL boundary used by session use cases.
type TokenState interface {
	BlacklistJTI(context.Context, string, time.Duration) error
	IsRefreshReuseMarked(context.Context, string) (bool, error)
	MarkRefreshReuse(context.Context, string, time.Duration) error
}

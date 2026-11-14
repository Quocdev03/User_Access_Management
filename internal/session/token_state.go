package session

import (
	"context"
	"time"
)

// File này định nghĩa Redis TTL boundary mà session use case được phép sử dụng.

// TokenState giới hạn session use case vào đúng các loại TTL state được phép lưu ở Redis.
type TokenState interface {
	// BlacklistJTI chặn một access-token JTI đến hết TTL còn lại của token.
	BlacklistJTI(context.Context, string, time.Duration) error
	// IsRefreshReuseMarked kiểm tra refresh token đã bị đánh dấu reuse hay chưa.
	IsRefreshReuseMarked(context.Context, string) (bool, error)
	// MarkRefreshReuse lưu marker reuse đến khi refresh token hết hiệu lực.
	MarkRefreshReuse(context.Context, string, time.Duration) error
}

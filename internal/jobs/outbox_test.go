package jobs

import (
	"testing"
	"time"
)

// File này kiểm chứng hành vi outbox và các trường hợp lỗi liên quan.

// TestOutboxBackoffIsBounded kiểm chứng kịch bản OutboxBackoffIsBounded.
func TestOutboxBackoffIsBounded(t *testing.T) {
	if got := outboxBackoff(1); got != 2*time.Second {
		t.Fatalf("attempt 1 backoff = %s, want 2s", got)
	}
	if got := outboxBackoff(100); got != 256*time.Second {
		t.Fatalf("bounded backoff = %s, want 256s", got)
	}
}

//go:build integration

package redisstore

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// File này kiểm chứng tích hợp mfa challenge integration với các dependency runtime liên quan.

// TestMFAChallengeClaimAttemptAndConsumeAreAtomic kiểm chứng kịch bản MFAChallengeClaimAttemptAndConsumeAreAtomic.
func TestMFAChallengeClaimAttemptAndConsumeAreAtomic(t *testing.T) {
	address := os.Getenv("UAM_REDIS_TEST_ADDR")
	if address == "" {
		t.Skip("UAM_REDIS_TEST_ADDR is not configured")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	store := NewMFAChallengeStore(client)
	ctx := context.Background()

	token, err := store.Create(ctx, MFAChallenge{
		UserID:      42,
		AuthVersion: 7,
	}, time.Minute)
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}
	t.Cleanup(func() { _ = client.Del(ctx, mfaChallengeKey(token)).Err() })

	start := make(chan struct{})
	results := make(chan bool, 2)
	errs := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, claimed, err := store.Claim(ctx, token, 3)
			results <- claimed
			errs <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(errs)
	claimedCount := 0
	for claimed := range results {
		if claimed {
			claimedCount++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Claim(): %v", err)
		}
	}
	if claimedCount != 1 {
		t.Fatalf("concurrent claims = %d, want 1", claimedCount)
	}

	var claimToken string
	if err := client.HGet(ctx, mfaChallengeKey(token), "claim_token").
		Scan(&claimToken); err != nil {
		t.Fatalf("read winning claim token: %v", err)
	}
	consumed, err := store.Finish(ctx, token, claimToken, false, 3)
	if err != nil || consumed {
		t.Fatalf("Finish(invalid) = consumed %v, err %v", consumed, err)
	}
	claim, claimed, err := store.Claim(ctx, token, 3)
	if err != nil || !claimed {
		t.Fatalf("Claim(after invalid) = %+v, %v, %v", claim, claimed, err)
	}
	if claim.Attempts != 1 ||
		claim.Challenge.UserID != 42 ||
		claim.Challenge.AuthVersion != 7 {
		t.Fatalf("claim payload = %+v", claim)
	}
	consumed, err = store.Finish(ctx, token, claim.ClaimToken, true, 3)
	if err != nil || !consumed {
		t.Fatalf("Finish(valid) = consumed %v, err %v", consumed, err)
	}
	if exists, err := client.Exists(ctx, mfaChallengeKey(token)).Result(); err != nil ||
		exists != 0 {
		t.Fatalf("consumed key exists=%d err=%v", exists, err)
	}
}

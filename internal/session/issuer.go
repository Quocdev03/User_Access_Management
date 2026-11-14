package session

import (
	"context"
	"fmt"
	"time"

	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

// File này phát hành token và lưu session trong transaction do caller sở hữu.

// IssueInput chứa thông tin người dùng và token cần thiết để phát hành một phiên đăng nhập mới.
type IssueInput struct {
	UserID       uint64
	RefreshToken string
	AccessJTI    string
	IPAddress    string
	UserAgent    string
}

// Issuer chịu trách nhiệm tạo mới session và quản lý giới hạn số lượng session đồng thời trong MySQL transaction.
type Issuer struct {
	sessions    *mysqlstore.SessionStore
	profiles    *mysqlstore.ClientProfileStore
	tokens      TokenState
	invalidator *Invalidator
	maxSessions int
	accessTTL   time.Duration
	refreshTTL  time.Duration
}

// NewIssuer khởi tạo Issuer với các dependency được cung cấp.
func NewIssuer(
	sessions *mysqlstore.SessionStore,
	profiles *mysqlstore.ClientProfileStore,
	tokens TokenState,
	invalidator *Invalidator,
	maxSessions int,
	accessTTL time.Duration,
	refreshTTL time.Duration,
) *Issuer {
	return &Issuer{
		sessions:    sessions,
		profiles:    profiles,
		tokens:      tokens,
		invalidator: invalidator,
		maxSessions: maxSessions,
		accessTTL:   accessTTL,
		refreshTTL:  refreshTTL,
	}
}

// IssueInTx phát hành token và lưu session bên trong transaction đăng nhập do caller sở hữu.
func (i *Issuer) IssueInTx(ctx context.Context, input IssueInput) ([]string, error) {
	var kickedJTIs []string
	if i.maxSessions > 0 {
		count, err := i.sessions.CountActiveByUserID(ctx, input.UserID)
		if err != nil {
			return nil, fmt.Errorf("count active sessions: %w", err)
		}
		if kick := sessionsToKick(count, i.maxSessions); kick > 0 {
			kickedJTIs, err = i.sessions.RevokeOldestActiveReturningJTI(
				ctx,
				input.UserID,
				kick,
			)
			if err != nil {
				return nil, fmt.Errorf("revoke oldest sessions: %w", err)
			}
		}
	}

	profile := observedClientProfile(input.UserID, input.IPAddress, input.UserAgent)
	var profileID *uint64
	if err := i.profiles.Observe(ctx, &profile); err != nil {
		return nil, err
	}
	profileID = &profile.ID

	session := &mysqlstore.Session{
		UserID:             input.UserID,
		CurrentRefreshHash: hash.SHA256(input.RefreshToken),
		AccessJTI:          input.AccessJTI,
		IPAddress:          &input.IPAddress,
		UserAgent:          &input.UserAgent,
		ClientProfileID:    profileID,
		ExpiresAt:          time.Now().UTC().Add(i.refreshTTL),
	}
	if err := i.sessions.Create(ctx, session); err != nil {
		return nil, err
	}
	return kickedJTIs, nil
}

// FinalizeEvictions blacklist JTI của các session bị đẩy sau khi transaction đã commit.
func (i *Issuer) FinalizeEvictions(
	ctx context.Context,
	userID uint64,
	kickedJTIs []string,
) error {
	for _, jti := range kickedJTIs {
		if err := i.tokens.BlacklistJTI(ctx, jti, i.accessTTL); err != nil {
			if invalidateErr := i.invalidator.InvalidateAll(ctx, userID); invalidateErr != nil {
				return fmt.Errorf(
					"blacklist evicted session JTI: %v; invalidate auth: %w",
					err,
					invalidateErr,
				)
			}
			return fmt.Errorf("blacklist evicted session JTI after auth invalidation: %w", err)
		}
	}
	return nil
}

// sessionsToKick tính số session cũ nhất cần thu hồi theo giới hạn cấu hình.
func sessionsToKick(activeCount, maximum int) int {
	if maximum <= 0 {
		return 0
	}
	needed := activeCount - (maximum - 1)
	if needed < 0 {
		return 0
	}
	return needed
}

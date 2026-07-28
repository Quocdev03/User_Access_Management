package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

type RotationRequest struct {
	UserID             uint64
	CurrentRefreshHash string
	RefreshExpiresAt   time.Time
	IPAddress          string
	UserAgent          string
}

type RotationTokens struct {
	AccessToken  string
	RefreshToken string
	AccessJTI    string
}

type RotationAuthorizer func(context.Context) (RotationTokens, error)

type Rotator struct {
	sessions    *mysqlstore.SessionStore
	tokens      TokenState
	invalidator *Invalidator
	txManager   *mysqlstore.TxManager
	accessTTL   time.Duration
	refreshTTL  time.Duration
}

func NewRotator(
	db *sqlx.DB,
	sessions *mysqlstore.SessionStore,
	tokens TokenState,
	invalidator *Invalidator,
	accessTTL time.Duration,
	refreshTTL time.Duration,
) *Rotator {
	return &Rotator{
		sessions:    sessions,
		tokens:      tokens,
		invalidator: invalidator,
		txManager:   mysqlstore.NewTxManager(db),
		accessTTL:   accessTTL,
		refreshTTL:  refreshTTL,
	}
}

func (r *Rotator) Rotate(
	ctx context.Context,
	request RotationRequest,
	authorize RotationAuthorizer,
) (RotationTokens, error) {
	reused, err := r.reuseDetected(ctx, request.CurrentRefreshHash)
	if err != nil {
		return RotationTokens{}, err
	}
	if reused {
		if err := r.invalidator.InvalidateAll(ctx, request.UserID); err != nil {
			return RotationTokens{}, fmt.Errorf("invalidate auth after refresh reuse: %w", err)
		}
		return RotationTokens{}, apperror.ErrTokenReuse
	}

	var result RotationTokens
	var oldAccessJTI string
	var committedBusinessError error
	err = r.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		current, err := r.sessions.FindByCurrentRefreshHashForUpdate(
			txCtx,
			request.CurrentRefreshHash,
		)
		if err != nil {
			return err
		}
		if current == nil {
			reused, err := r.sessions.RefreshHistoryExists(txCtx, request.CurrentRefreshHash)
			if err != nil {
				return err
			}
			if reused {
				return apperror.ErrTokenReuse
			}
			committedBusinessError = apperror.ErrSessionExpired
			return nil
		}
		if current.UserID != request.UserID {
			return apperror.ErrRefreshTokenInvalid
		}
		if !current.ExpiresAt.After(time.Now().UTC()) {
			if err := r.sessions.RevokeLocked(txCtx, current.ID, current.UserID); err != nil {
				return err
			}
			committedBusinessError = apperror.ErrRefreshTokenInvalid
			return nil
		}

		result, err = authorize(txCtx)
		if err != nil {
			return err
		}
		oldAccessJTI = current.AccessJTI

		current.CurrentRefreshHash = hash.SHA256(result.RefreshToken)
		current.AccessJTI = result.AccessJTI
		current.IPAddress = &request.IPAddress
		current.UserAgent = &request.UserAgent
		current.ExpiresAt = time.Now().UTC().Add(r.refreshTTL)
		return r.sessions.Rotate(
			txCtx,
			current,
			request.CurrentRefreshHash,
			request.RefreshExpiresAt,
		)
	})
	if err != nil {
		if errors.Is(err, apperror.ErrTokenReuse) {
			if invalidateErr := r.invalidator.InvalidateAll(ctx, request.UserID); invalidateErr != nil {
				return RotationTokens{}, fmt.Errorf(
					"invalidate auth after concurrent refresh reuse: %w",
					invalidateErr,
				)
			}
		}
		return RotationTokens{}, err
	}
	if committedBusinessError != nil {
		return RotationTokens{}, committedBusinessError
	}

	if ttl := time.Until(request.RefreshExpiresAt); ttl > 0 {
		if err := r.tokens.MarkRefreshReuse(ctx, request.CurrentRefreshHash, ttl); err != nil {
			return RotationTokens{}, r.compensateTokenStateFailure(
				ctx,
				request.UserID,
				"mark rotated refresh token",
				err,
			)
		}
	}
	if oldAccessJTI != "" {
		if err := r.tokens.BlacklistJTI(ctx, oldAccessJTI, r.accessTTL); err != nil {
			return RotationTokens{}, r.compensateTokenStateFailure(
				ctx,
				request.UserID,
				"blacklist rotated access JTI",
				err,
			)
		}
	}
	return result, nil
}

func (r *Rotator) reuseDetected(ctx context.Context, refreshHash string) (bool, error) {
	marked, err := r.tokens.IsRefreshReuseMarked(ctx, refreshHash)
	if err != nil {
		return false, fmt.Errorf("check refresh reuse marker: %w", err)
	}
	inHistory, err := r.sessions.RefreshHistoryExists(ctx, refreshHash)
	if err != nil {
		return false, err
	}
	return marked || inHistory, nil
}

func (r *Rotator) compensateTokenStateFailure(
	ctx context.Context,
	userID uint64,
	operation string,
	cause error,
) error {
	if err := r.invalidator.InvalidateAll(ctx, userID); err != nil {
		return fmt.Errorf("%s: %v; invalidate auth: %w", operation, cause, err)
	}
	return fmt.Errorf("%s after auth invalidation: %w", operation, cause)
}

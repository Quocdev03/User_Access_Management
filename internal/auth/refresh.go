package auth

import (
	"context"
	"errors"
	"time"

	accessapp "github.com/quocdev03/user-access-management/internal/access"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	sessionapp "github.com/quocdev03/user-access-management/internal/session"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
	"github.com/quocdev03/user-access-management/pkg/jwt"
	"go.uber.org/zap"
)

type RefreshCommand struct {
	RefreshToken string
	IPAddress    string
	UserAgent    string
}

type RefreshResult struct {
	AccessToken  string
	RefreshToken string
}

type Refresh struct {
	accounts *mysqlstore.AccountStore
	roles    *mysqlstore.RoleStore
	rotator  *sessionapp.Rotator
	policy   TokenPolicy
	logger   *zap.Logger
}

func NewRefresh(
	accounts *mysqlstore.AccountStore,
	roles *mysqlstore.RoleStore,
	rotator *sessionapp.Rotator,
	policy TokenPolicy,
	logger *zap.Logger,
) *Refresh {
	return &Refresh{
		accounts: accounts,
		roles:    roles,
		rotator:  rotator,
		policy:   policy,
		logger:   logger,
	}
}

func (r *Refresh) Rotate(
	ctx context.Context,
	command RefreshCommand,
) (RefreshResult, error) {
	ipAddress, userAgent := sessionapp.NormalizeRequestMeta(
		command.IPAddress,
		command.UserAgent,
	)
	claims, err := jwt.ParseToken(command.RefreshToken, r.policy.JWTSecret)
	if err != nil {
		return RefreshResult{}, apperror.ErrRefreshTokenInvalid
	}
	if claims.Type != tokenTypeRefresh {
		return RefreshResult{}, apperror.ErrNotRefreshToken
	}

	currentHash := hash.SHA256(command.RefreshToken)
	rotated, err := r.rotator.Rotate(
		ctx,
		sessionapp.RotationRequest{
			UserID:             claims.UserID,
			CurrentRefreshHash: currentHash,
			RefreshExpiresAt:   claims.ExpiresAt.Time,
			IPAddress:          ipAddress,
			UserAgent:          userAgent,
		},
		func(txCtx context.Context) (sessionapp.RotationTokens, error) {
			account, err := r.accounts.FindByID(txCtx, claims.UserID)
			if err != nil {
				return sessionapp.RotationTokens{}, err
			}
			if account == nil {
				return sessionapp.RotationTokens{}, apperror.ErrAccountDisabled
			}
			state, err := account.State()
			if err != nil {
				return sessionapp.RotationTokens{}, err
			}
			if state.AuthVersion != claims.AuthVersion {
				return sessionapp.RotationTokens{}, apperror.ErrSessionExpired
			}
			now := time.Now().UTC()
			state.UnlockLoginIfExpired(now)
			if err := state.AuthenticationError(now); err != nil {
				return sessionapp.RotationTokens{}, err
			}
			roles, err := r.roles.NamesByUserID(txCtx, account.ID)
			if err != nil {
				return sessionapp.RotationTokens{}, err
			}
			if len(roles) == 0 {
				roles = []string{accessapp.RoleUser}
			}
			accessToken, refreshToken, accessJTI, err := generateTokenPair(
				account.ID,
				state.AuthVersion,
				roles,
				r.policy,
			)
			if err != nil {
				return sessionapp.RotationTokens{}, err
			}
			return sessionapp.RotationTokens{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				AccessJTI:    accessJTI,
			}, nil
		},
	)
	if err != nil {
		if errors.Is(err, apperror.ErrTokenReuse) {
			r.logger.Warn(
				"Phát hiện refresh token reuse",
				zap.Uint64("user_id", claims.UserID),
			)
		}
		return RefreshResult{}, err
	}
	return RefreshResult{
		AccessToken:  rotated.AccessToken,
		RefreshToken: rotated.RefreshToken,
	}, nil
}

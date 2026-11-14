package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	sessionapp "github.com/quocdev03/user-access-management/internal/session"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
	"go.uber.org/zap"
)

// File này điều phối đăng nhập, khóa bản ghi và phát hành session nguyên tử.

// LoginPolicy cấu hình giới hạn số lần đăng nhập sai, thời gian khóa tài khoản và chính sách token.
type LoginPolicy struct {
	TokenPolicy
	MaxFailedAttempts int
	LockDuration      time.Duration
}

// LoginCommand chứa thông tin xác thực đăng nhập bao gồm email, mật khẩu, IP và User-Agent.
type LoginCommand struct {
	Email     string
	Password  string
	IPAddress string
	UserAgent string
}

// LoginResult chứa kết quả đăng nhập thành công gồm các token hoặc yêu cầu thử thách MFA.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	UserID       uint64
	Username     string
	Email        string
	FullName     string
	MFARequired  bool
	MFAChallenge string
}

// Login thực thi use case xác thực đăng nhập người dùng, kiểm tra khóa tài khoản và khởi tạo session.
type Login struct {
	accounts  *mysqlstore.AccountStore
	profiles  *mysqlstore.ProfileStore
	roles     *mysqlstore.RoleStore
	audits    *mysqlstore.AuditStore
	issuer    *sessionapp.Issuer
	mfa       *MFA
	txManager *mysqlstore.TxManager
	policy    LoginPolicy
	logger    *zap.Logger
}

// NewLogin khởi tạo Login với các dependency được cung cấp.
func NewLogin(
	db *sqlx.DB,
	accounts *mysqlstore.AccountStore,
	profiles *mysqlstore.ProfileStore,
	roles *mysqlstore.RoleStore,
	audits *mysqlstore.AuditStore,
	issuer *sessionapp.Issuer,
	mfa *MFA,
	policy LoginPolicy,
	logger *zap.Logger,
) *Login {
	return &Login{
		accounts:  accounts,
		profiles:  profiles,
		roles:     roles,
		audits:    audits,
		issuer:    issuer,
		mfa:       mfa,
		txManager: mysqlstore.NewTxManager(db),
		policy:    policy,
		logger:    logger,
	}
}

// Authenticate xác thực credential theo thứ tự chống timing leak, khóa account trước mutation và phát hành session trong cùng transaction.
func (l *Login) Authenticate(
	ctx context.Context,
	command LoginCommand,
) (LoginResult, error) {
	ipAddress, userAgent := sessionapp.NormalizeRequestMeta(
		command.IPAddress,
		command.UserAgent,
	)
	account, err := l.accounts.FindByEmail(ctx, command.Email)
	if err != nil {
		return LoginResult{}, err
	}
	if account == nil {
		_ = hash.CheckPassword("dummy-password", hash.DummyPasswordHash)
		return LoginResult{}, apperror.ErrInvalidCredentials
	}

	now := time.Now().UTC()
	snapshotState, err := account.State()
	if err != nil {
		return LoginResult{}, err
	}
	snapshotState.UnlockLoginIfExpired(now)

	passwordHashSnapshot := account.PasswordHash
	passwordMatches := hash.CheckPassword(command.Password, passwordHashSnapshot)
	var (
		result         LoginResult
		kickedJTIs     []string
		businessError  error
		auditStatus    string
		mfaRequired    bool
		mfaUserID      uint64
		mfaAuthVersion uint64
	)
	err = l.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		locked, err := l.accounts.FindByIDForUpdate(txCtx, account.ID)
		if err != nil {
			return err
		}
		if locked == nil {
			businessError = apperror.ErrInvalidCredentials
			return nil
		}
		state, err := locked.State()
		if err != nil {
			return err
		}
		unlocked := state.UnlockLoginIfExpired(now)

		snapshotMatches := subtle.ConstantTimeCompare(
			[]byte(locked.PasswordHash),
			[]byte(passwordHashSnapshot),
		) == 1
		if !snapshotMatches {
			if unlocked {
				if err := l.accounts.UpdateLoginState(
					txCtx,
					locked.ID,
					state,
					nil,
					now,
				); err != nil {
					return err
				}
			}
			businessError = apperror.ErrInvalidCredentials
			auditStatus = "failure"
			return nil
		}

		if !passwordMatches {
			if err := state.AuthenticationError(now); err != nil {
				if unlocked {
					if err := l.accounts.UpdateLoginState(
						txCtx,
						locked.ID,
						state,
						nil,
						now,
					); err != nil {
						return err
					}
				}
				businessError = apperror.ErrInvalidCredentials
				auditStatus = "failure"
				return nil
			}
			state.RecordFailedLogin(
				now,
				l.policy.MaxFailedAttempts,
				l.policy.LockDuration,
			)
			if err := l.accounts.UpdateLoginState(
				txCtx,
				locked.ID,
				state,
				nil,
				now,
			); err != nil {
				return err
			}
			auditStatus = "failure"
			if state.LoginLockedUntil != nil &&
				state.LoginLockedUntil.After(now) {
				businessError = apperror.ErrAccountLocked.WithMessage(
					fmt.Sprintf(
						"Tài khoản bị khóa %d phút do nhập sai mật khẩu %d lần",
						int(l.policy.LockDuration.Minutes()),
						l.policy.MaxFailedAttempts,
					),
				)
			} else {
				businessError = apperror.ErrInvalidCredentials
			}
			return nil
		}

		if err := state.AuthenticationError(now); err != nil {
			businessError = err
			auditStatus = "failure"
			return nil
		}
		if state.PasswordChangeRequired {
			if unlocked {
				if err := l.accounts.UpdateLoginState(
					txCtx,
					locked.ID,
					state,
					nil,
					now,
				); err != nil {
					return err
				}
			}
			businessError = apperror.ErrMustChangePassword
			auditStatus = "failure_must_change_password"
			return nil
		}

		mfaEnabled, err := l.mfa.EnabledForLogin(txCtx, locked.ID)
		if err != nil {
			return err
		}
		if mfaEnabled {
			mfaRequired = true
			mfaUserID = locked.ID
			mfaAuthVersion = state.AuthVersion
			auditStatus = "mfa_required"
			return nil
		}

		profile, err := l.profiles.FindByUserID(txCtx, locked.ID)
		if err != nil {
			return err
		}
		if profile == nil {
			return fmt.Errorf("account %d canonical profile is not backfilled", locked.ID)
		}
		roles, err := l.roles.NamesByUserID(txCtx, locked.ID)
		if err != nil {
			return err
		}
		if roles == nil {
			roles = []string{}
		}

		accessToken, refreshToken, accessJTI, err := generateTokenPair(
			locked.ID,
			state.AuthVersion,
			roles,
			l.policy.TokenPolicy,
		)
		if err != nil {
			return err
		}
		state.CompleteAuthentication()
		if err := l.accounts.UpdateLoginState(
			txCtx,
			locked.ID,
			state,
			&now,
			now,
		); err != nil {
			return err
		}
		kickedJTIs, err = l.issuer.IssueInTx(txCtx, sessionapp.IssueInput{
			UserID:       locked.ID,
			RefreshToken: refreshToken,
			AccessJTI:    accessJTI,
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
		})
		if err != nil {
			return err
		}
		result = LoginResult{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			UserID:       locked.ID,
			Username:     locked.Username,
			Email:        locked.Email,
			FullName:     profile.FullName,
		}
		auditStatus = "success"
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	if businessError != nil {
		if auditStatus != "" {
			l.logAudit(ctx, account.ID, ipAddress, userAgent, auditStatus)
		}
		return LoginResult{}, businessError
	}
	if mfaRequired {
		challenge, err := l.mfa.CreateLoginChallenge(
			ctx,
			mfaUserID,
			mfaAuthVersion,
		)
		if err != nil {
			return LoginResult{}, err
		}
		l.logAudit(ctx, account.ID, ipAddress, userAgent, auditStatus)
		return LoginResult{
			UserID:       mfaUserID,
			MFARequired:  true,
			MFAChallenge: challenge,
		}, nil
	}
	if err := l.issuer.FinalizeEvictions(ctx, account.ID, kickedJTIs); err != nil {
		return LoginResult{}, err
	}
	l.logAudit(ctx, account.ID, ipAddress, userAgent, auditStatus)
	return result, nil
}

// logAudit ghi kết quả đăng nhập theo best effort và cảnh báo khi audit store thất bại.
func (l *Login) logAudit(
	ctx context.Context,
	userID uint64,
	ipAddress string,
	userAgent string,
	status string,
) {
	resource := "auth"
	if err := l.audits.Create(ctx, &mysqlstore.AuditLog{
		UserID:    &userID,
		Action:    "LOGIN",
		Resource:  &resource,
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
		Status:    status,
	}); err != nil {
		l.logger.Warn(
			"Không thể ghi audit log",
			zap.String("action", "LOGIN"),
			zap.Error(err),
		)
	}
}

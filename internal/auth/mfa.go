package auth

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/accountstate"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	sessionapp "github.com/quocdev03/user-access-management/internal/session"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

// File này điều phối setup, xác nhận, tắt MFA và recovery codes.

// MFAPolicy cấu hình các tham số bảo mật cho xác thực đa yếu tố (MFA).
type MFAPolicy struct {
	Issuer            string
	ChallengeTTL      time.Duration
	MaxAttempts       int
	RecoveryCodeCount int
	MaxFailedAttempts int
	LockDuration      time.Duration
	TokenPolicy       TokenPolicy
}

// MFADependencies tập hợp các dependency cần thiết để khởi tạo use case MFA.
type MFADependencies struct {
	DB              *sqlx.DB
	Accounts        *mysqlstore.AccountStore
	Profiles        *mysqlstore.ProfileStore
	Roles           *mysqlstore.RoleStore
	Audits          *mysqlstore.AuditStore
	Store           *mysqlstore.MFAStore
	Challenges      *redisstore.MFAChallengeStore
	Issuer          *sessionapp.Issuer
	AuthInvalidator *mysqlstore.AuthInvalidator
	Codec           *MFASecretCodec
}

// MFA quản lý toàn bộ vòng đời xác thực đa yếu tố bao gồm setup, kích hoạt, xác thực và vô hiệu hóa.
type MFA struct {
	accounts        *mysqlstore.AccountStore
	profiles        *mysqlstore.ProfileStore
	roles           *mysqlstore.RoleStore
	audits          *mysqlstore.AuditStore
	store           *mysqlstore.MFAStore
	challenges      *redisstore.MFAChallengeStore
	issuer          *sessionapp.Issuer
	authInvalidator *mysqlstore.AuthInvalidator
	codec           *MFASecretCodec
	txManager       *mysqlstore.TxManager
	policy          MFAPolicy
}

// MFASetupResult chứa secret và URI mã hóa QR code phục vụ thiết lập MFA.
type MFASetupResult struct {
	Secret        string
	EnrollmentURI string
}

// MFAStatusResult phản ánh trạng thái kích hoạt MFA và số mã khôi phục còn lại.
type MFAStatusResult struct {
	Enabled                bool
	RecoveryCodesRemaining int
}

// NewMFA khởi tạo MFA với các dependency được cung cấp.
func NewMFA(deps MFADependencies, policy MFAPolicy) *MFA {
	return &MFA{
		accounts:        deps.Accounts,
		profiles:        deps.Profiles,
		roles:           deps.Roles,
		audits:          deps.Audits,
		store:           deps.Store,
		challenges:      deps.Challenges,
		issuer:          deps.Issuer,
		authInvalidator: deps.AuthInvalidator,
		codec:           deps.Codec,
		txManager:       mysqlstore.NewTxManager(deps.DB),
		policy:          policy,
	}
}

// Setup tạo TOTP enrollment mới nhưng chưa bật MFA cho đến bước Confirm.
func (m *MFA) Setup(
	ctx context.Context,
	userID uint64,
	currentPassword string,
	metadata PasswordMetadata,
) (MFASetupResult, error) {
	proof, err := m.preparePasswordProof(ctx, userID, currentPassword)
	if err != nil {
		return MFASetupResult{}, err
	}
	if !proof.passwordMatches {
		return MFASetupResult{}, m.runPasswordProofTx(
			ctx,
			proof,
			nil,
		)
	}

	secret, enrollmentURI, err := generateTOTPEnrollment(
		m.policy.Issuer,
		proof.account.Email,
	)
	if err != nil {
		return MFASetupResult{}, err
	}
	ciphertext, keyVersion, err := m.codec.Encrypt(userID, secret)
	if err != nil {
		return MFASetupResult{}, err
	}

	err = m.runPasswordProofTx(
		ctx,
		proof,
		func(
			txCtx context.Context,
			account *mysqlstore.Account,
			_ *accountstate.State,
			now time.Time,
		) error {
			record, err := m.store.FindByUserIDForUpdate(txCtx, account.ID)
			if err != nil {
				return err
			}
			if record != nil && record.EnabledAt != nil {
				return apperror.ErrMFAAlreadyEnabled
			}
			if record == nil {
				err = m.store.CreatePending(txCtx, &mysqlstore.TOTPRecord{
					UserID:           account.ID,
					SecretCiphertext: ciphertext,
					KeyVersion:       keyVersion,
				}, now)
			} else {
				err = m.store.ReplacePending(
					txCtx,
					account.ID,
					ciphertext,
					keyVersion,
					now,
				)
			}
			if err != nil {
				return err
			}
			return m.auditMutation(
				txCtx,
				account.ID,
				"MFA_SETUP_STARTED",
				metadata,
			)
		},
	)
	if err != nil {
		return MFASetupResult{}, err
	}
	return MFASetupResult{
		Secret:        secret,
		EnrollmentURI: enrollmentURI,
	}, nil
}

// Confirm xác minh TOTP đầu tiên rồi bật MFA và vô hiệu hóa session trong transaction.
func (m *MFA) Confirm(
	ctx context.Context,
	userID uint64,
	expectedAuthVersion uint64,
	code string,
	metadata PasswordMetadata,
) ([]string, error) {
	now := time.Now().UTC()
	record, err := m.store.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if record == nil || record.EnabledAt != nil {
		return nil, apperror.ErrMFASetupRequired
	}
	secret, err := m.codec.Decrypt(
		userID,
		record.KeyVersion,
		record.SecretCiphertext,
	)
	if err != nil {
		return nil, err
	}
	usedStep, valid, err := validateTOTPCode(secret, code, now)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, apperror.ErrMFAInvalid
	}
	recoveryCodes, recoveryHashes, err := generateRecoveryCodes(
		m.policy.RecoveryCodeCount,
	)
	if err != nil {
		return nil, err
	}

	var businessError error
	err = m.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := m.accounts.FindByIDForUpdate(txCtx, userID)
		if err != nil {
			return err
		}
		if account == nil {
			businessError = apperror.ErrNotFound
			return nil
		}
		state, err := account.State()
		if err != nil {
			return err
		}
		state.UnlockLoginIfExpired(now)
		if state.AuthVersion != expectedAuthVersion {
			businessError = apperror.ErrUnauthorized
			return nil
		}
		if err := state.AuthenticationError(now); err != nil {
			businessError = err
			return nil
		}
		locked, err := m.store.FindByUserIDForUpdate(txCtx, userID)
		if err != nil {
			return err
		}
		if !sameMFASnapshot(locked, record) || locked.EnabledAt != nil {
			businessError = apperror.ErrMFASetupRequired
			return nil
		}
		if err := m.store.Enable(txCtx, userID, usedStep, now); err != nil {
			return err
		}
		if err := m.store.ReplaceRecoveryCodes(
			txCtx,
			userID,
			recoveryHashes,
			now,
		); err != nil {
			return err
		}
		state.InvalidateAuth()
		if err := m.accounts.UpdateState(txCtx, userID, state, now); err != nil {
			return err
		}
		if err := m.authInvalidator.DeleteSessions(txCtx, userID); err != nil {
			return err
		}
		return m.auditMutation(txCtx, userID, "MFA_ENABLED", metadata)
	})
	if err != nil {
		return nil, err
	}
	if businessError != nil {
		return nil, businessError
	}
	return recoveryCodes, nil
}

// Disable xác minh password/TOTP rồi xóa factor và session trong transaction.
func (m *MFA) Disable(
	ctx context.Context,
	userID uint64,
	currentPassword string,
	code string,
	metadata PasswordMetadata,
) error {
	proof, err := m.preparePasswordProof(ctx, userID, currentPassword)
	if err != nil {
		return err
	}
	if !proof.passwordMatches {
		return m.runPasswordProofTx(ctx, proof, nil)
	}
	factor, err := m.prepareEnabledFactor(ctx, userID, code, proof.now)
	if err != nil {
		return err
	}
	return m.runPasswordProofTx(
		ctx,
		proof,
		func(
			txCtx context.Context,
			account *mysqlstore.Account,
			state *accountstate.State,
			now time.Time,
		) error {
			locked, err := m.store.FindByUserIDForUpdate(txCtx, account.ID)
			if err != nil {
				return err
			}
			if !sameMFASnapshot(locked, factor.record) || locked.EnabledAt == nil {
				return apperror.ErrMFANotEnabled
			}
			if err := m.consumeFactor(txCtx, account.ID, factor, now); err != nil {
				return err
			}
			if err := m.store.Delete(txCtx, account.ID); err != nil {
				return err
			}
			state.InvalidateAuth()
			if err := m.accounts.UpdateState(txCtx, account.ID, *state, now); err != nil {
				return err
			}
			if err := m.authInvalidator.DeleteSessions(txCtx, account.ID); err != nil {
				return err
			}
			return m.auditMutation(txCtx, account.ID, "MFA_DISABLED", metadata)
		},
	)
}

// RegenerateRecoveryCodes thay toàn bộ recovery code sau khi xác minh password và TOTP.
func (m *MFA) RegenerateRecoveryCodes(
	ctx context.Context,
	userID uint64,
	currentPassword string,
	code string,
	metadata PasswordMetadata,
) ([]string, error) {
	proof, err := m.preparePasswordProof(ctx, userID, currentPassword)
	if err != nil {
		return nil, err
	}
	if !proof.passwordMatches {
		return nil, m.runPasswordProofTx(ctx, proof, nil)
	}
	factor, err := m.prepareEnabledFactor(ctx, userID, code, proof.now)
	if err != nil {
		return nil, err
	}
	recoveryCodes, recoveryHashes, err := generateRecoveryCodes(
		m.policy.RecoveryCodeCount,
	)
	if err != nil {
		return nil, err
	}
	err = m.runPasswordProofTx(
		ctx,
		proof,
		func(
			txCtx context.Context,
			account *mysqlstore.Account,
			state *accountstate.State,
			now time.Time,
		) error {
			locked, err := m.store.FindByUserIDForUpdate(txCtx, account.ID)
			if err != nil {
				return err
			}
			if !sameMFASnapshot(locked, factor.record) || locked.EnabledAt == nil {
				return apperror.ErrMFANotEnabled
			}
			if err := m.consumeFactor(txCtx, account.ID, factor, now); err != nil {
				return err
			}
			if err := m.store.ReplaceRecoveryCodes(
				txCtx,
				account.ID,
				recoveryHashes,
				now,
			); err != nil {
				return err
			}
			state.InvalidateAuth()
			if err := m.accounts.UpdateState(txCtx, account.ID, *state, now); err != nil {
				return err
			}
			if err := m.authInvalidator.DeleteSessions(txCtx, account.ID); err != nil {
				return err
			}
			return m.auditMutation(
				txCtx,
				account.ID,
				"MFA_RECOVERY_REGENERATED",
				metadata,
			)
		},
	)
	if err != nil {
		return nil, err
	}
	return recoveryCodes, nil
}

// Status trả trạng thái MFA và số recovery code còn hiệu lực của tài khoản.
func (m *MFA) Status(
	ctx context.Context,
	userID uint64,
) (MFAStatusResult, error) {
	record, err := m.store.FindByUserID(ctx, userID)
	if err != nil {
		return MFAStatusResult{}, err
	}
	if record == nil || record.EnabledAt == nil {
		return MFAStatusResult{}, nil
	}
	count, err := m.store.CountUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return MFAStatusResult{}, err
	}
	return MFAStatusResult{
		Enabled:                true,
		RecoveryCodesRemaining: count,
	}, nil
}

// EnabledForLogin kiểm tra MFA flag bằng transaction context của login use case.
func (m *MFA) EnabledForLogin(
	ctx context.Context,
	userID uint64,
) (bool, error) {
	record, err := m.store.FindByUserIDForUpdate(ctx, userID)
	if err != nil {
		return false, err
	}
	return record != nil && record.EnabledAt != nil, nil
}

// CreateLoginChallenge tạo đăng nhập challenge trong auth use case.
func (m *MFA) CreateLoginChallenge(
	ctx context.Context,
	userID uint64,
	authVersion uint64,
) (string, error) {
	return m.challenges.Create(ctx, redisstore.MFAChallenge{
		UserID:      userID,
		AuthVersion: authVersion,
	}, m.policy.ChallengeTTL)
}

// mfaPasswordProof lưu kết quả xác thực mật khẩu trước khi tiến hành cập nhật cấu hình MFA.
type mfaPasswordProof struct {
	account         *mysqlstore.Account
	passwordMatches bool
	now             time.Time
}

// preparePasswordProof đọc password snapshot và chạy bcrypt trước khi khóa account để giảm thời gian giữ lock.
func (m *MFA) preparePasswordProof(
	ctx context.Context,
	userID uint64,
	currentPassword string,
) (mfaPasswordProof, error) {
	account, err := m.accounts.FindByID(ctx, userID)
	if err != nil {
		return mfaPasswordProof{}, err
	}
	if account == nil {
		return mfaPasswordProof{}, apperror.ErrNotFound
	}
	state, err := account.State()
	if err != nil {
		return mfaPasswordProof{}, err
	}
	now := time.Now().UTC()
	state.UnlockLoginIfExpired(now)
	passwordMatches := hash.CheckPassword(currentPassword, account.PasswordHash)
	if passwordMatches {
		if err := state.AuthenticationError(now); err != nil {
			return mfaPasswordProof{}, err
		}
	}
	return mfaPasswordProof{
		account:         account,
		passwordMatches: passwordMatches,
		now:             now,
	}, nil
}

// runPasswordProofTx khóa account và chỉ chạy mutation khi password snapshot vẫn khớp.
func (m *MFA) runPasswordProofTx(
	ctx context.Context,
	proof mfaPasswordProof,
	mutation func(
		context.Context,
		*mysqlstore.Account,
		*accountstate.State,
		time.Time,
	) error,
) error {
	var businessError error
	err := m.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := m.accounts.FindByIDForUpdate(txCtx, proof.account.ID)
		if err != nil {
			return err
		}
		if account == nil {
			businessError = apperror.ErrNotFound
			return nil
		}
		samePassword := subtle.ConstantTimeCompare(
			[]byte(account.PasswordHash),
			[]byte(proof.account.PasswordHash),
		) == 1
		state, err := account.State()
		if err != nil {
			return err
		}
		snapshotState, err := proof.account.State()
		if err != nil {
			return err
		}
		if !samePassword || state.AuthVersion != snapshotState.AuthVersion {
			businessError = apperror.ErrInvalidCredentials
			return nil
		}
		state.UnlockLoginIfExpired(proof.now)
		if !proof.passwordMatches {
			if err := state.AuthenticationError(proof.now); err != nil {
				businessError = apperror.ErrInvalidCredentials
				return nil
			}
			state.RecordFailedLogin(
				proof.now,
				m.policy.MaxFailedAttempts,
				m.policy.LockDuration,
			)
			if err := m.accounts.UpdateState(
				txCtx,
				account.ID,
				state,
				proof.now,
			); err != nil {
				return err
			}
			businessError = apperror.ErrInvalidCredentials
			if state.LoginLockedUntil != nil {
				businessError = apperror.ErrAccountLocked
			}
			return nil
		}
		if err := state.AuthenticationError(proof.now); err != nil {
			businessError = err
			return nil
		}
		if mutation == nil {
			return nil
		}
		if err := mutation(txCtx, account, &state, proof.now); err != nil {
			if _, ok := err.(*apperror.AppError); ok {
				businessError = err
				return nil
			}
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return businessError
}

// mfaFactorProof lưu thông tin bản ghi TOTP và bước xác thực trước transaction mutation.
type mfaFactorProof struct {
	record       *mysqlstore.TOTPRecord
	usedStep     *uint64
	recoveryHash []byte
}

// prepareEnabledFactor giải mã TOTP secret hiện tại trước transaction mutation.
func (m *MFA) prepareEnabledFactor(
	ctx context.Context,
	userID uint64,
	code string,
	now time.Time,
) (mfaFactorProof, error) {
	record, err := m.store.FindByUserID(ctx, userID)
	if err != nil {
		return mfaFactorProof{}, err
	}
	if record == nil || record.EnabledAt == nil {
		return mfaFactorProof{}, apperror.ErrMFANotEnabled
	}
	secret, err := m.codec.Decrypt(
		userID,
		record.KeyVersion,
		record.SecretCiphertext,
	)
	if err != nil {
		return mfaFactorProof{}, err
	}
	usedStep, valid, err := validateTOTPCode(secret, code, now)
	if err != nil {
		return mfaFactorProof{}, err
	}
	if valid {
		return mfaFactorProof{
			record:   record,
			usedStep: &usedStep,
		}, nil
	}
	codeHash, valid := recoveryCodeHash(code)
	if !valid {
		return mfaFactorProof{}, apperror.ErrMFAInvalid
	}
	return mfaFactorProof{
		record:       record,
		recoveryHash: codeHash,
	}, nil
}

// consumeFactor consume factor trong auth use case.
func (m *MFA) consumeFactor(
	ctx context.Context,
	userID uint64,
	proof mfaFactorProof,
	now time.Time,
) error {
	if proof.usedStep != nil {
		consumed, err := m.store.MarkTOTPUsed(
			ctx,
			userID,
			*proof.usedStep,
			now,
		)
		if err != nil {
			return err
		}
		if !consumed {
			return apperror.ErrMFAInvalid
		}
		return nil
	}
	consumed, err := m.store.ConsumeRecoveryCode(
		ctx,
		userID,
		proof.recoveryHash,
		now,
	)
	if err != nil {
		return err
	}
	if !consumed {
		return apperror.ErrMFAInvalid
	}
	return nil
}

// auditMutation ghi MFA mutation theo best effort và không làm rollback kết quả chính.
func (m *MFA) auditMutation(
	ctx context.Context,
	userID uint64,
	action string,
	metadata PasswordMetadata,
) error {
	resource := "auth"
	status := "success"
	return m.audits.Create(ctx, &mysqlstore.AuditLog{
		UserID:    &userID,
		Action:    action,
		Resource:  &resource,
		IPAddress: &metadata.IPAddress,
		UserAgent: &metadata.UserAgent,
		Status:    status,
	})
}

// sameMFASnapshot phát hiện MFA state đã đổi giữa bước crypto và bước locked mutation.
func sameMFASnapshot(
	current *mysqlstore.TOTPRecord,
	snapshot *mysqlstore.TOTPRecord,
) bool {
	if current == nil || snapshot == nil {
		return false
	}
	return current.KeyVersion == snapshot.KeyVersion &&
		subtle.ConstantTimeCompare(
			current.SecretCiphertext,
			snapshot.SecretCiphertext,
		) == 1
}

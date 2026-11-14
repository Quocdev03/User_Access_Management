package access

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/accountstate"
	"github.com/quocdev03/user-access-management/internal/blob"
	"github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

// File này điều phối các mutation quản trị người dùng và hệ quả lên session.

// UserListQuery chứa các tham số tìm kiếm, lọc và phân trang danh sách người dùng cho quản trị viên.
type UserListQuery struct {
	Username  string
	Email     string
	Status    string
	Role      string
	SortBy    string
	SortOrder string
	Page      int
	PerPage   int
}

// User đại diện cho thông tin tài khoản người dùng đầy đủ trong ngữ cảnh quản trị.
type User struct {
	ID            uint64
	Username      string
	Email         string
	FullName      string
	Phone         string
	Status        string
	EmailVerified bool
	DateOfBirth   time.Time
	AvatarURL     *string
	Roles         []string
	CreatedAt     time.Time
}

// UserPage đóng gói danh sách người dùng cùng metadata phân trang kết quả tìm kiếm.
type UserPage struct {
	Users      []User
	Page       int
	PerPage    int
	Total      int64
	TotalPages int
}

// UpdateUserCommand chứa dữ liệu cập nhật thông tin người dùng do quản trị viên thực hiện.
type UpdateUserCommand struct {
	ActorID         uint64
	TargetID        uint64
	FullName        *string
	Phone           *string
	Email           *string
	EmailVerified   *bool
	DateOfBirth     *string
	AvatarObjectKey *string
	Metadata        Metadata
}

// ChangeStatusCommand chứa tham số thay đổi trạng thái hoạt động của tài khoản người dùng.
type ChangeStatusCommand struct {
	ActorID  uint64
	TargetID uint64
	Status   string
	Metadata Metadata
}

// ResetPasswordCommand chứa tham số yêu cầu đặt lại mật khẩu người dùng do quản trị viên khởi tạo.
type ResetPasswordCommand struct {
	ActorID  uint64
	TargetID uint64
	Metadata Metadata
}

// NotifyUserCommand chứa nội dung thông báo gửi tới người dùng thông qua outbox mail.
type NotifyUserCommand struct {
	ActorID  uint64
	TargetID uint64
	Subject  string
	Message  string
	Metadata Metadata
}

// Users cung cấp các use case quản lý thông tin, trạng thái và bảo mật người dùng cho quản trị viên.
type Users struct {
	access       *mysqlstore.AccessStore
	accounts     *mysqlstore.AccountStore
	profiles     *mysqlstore.ProfileStore
	emailChanges *mysqlstore.EmailChangeStore
	passwords    *mysqlstore.PasswordResetStore
	outbox       *mysqlstore.OutboxStore
	audits       *mysqlstore.AuditStore
	invalidator  *mysqlstore.AuthInvalidator
	txManager    *mysqlstore.TxManager
	lastAdmin    *LastAdminGuard
	codec        *mail.SecretCodec
	blobs        blob.Store
	resetExpiry  time.Duration
}

// NewUsers khởi tạo Users với các dependency được cung cấp.
func NewUsers(
	db *sqlx.DB,
	accessStore *mysqlstore.AccessStore,
	accounts *mysqlstore.AccountStore,
	profiles *mysqlstore.ProfileStore,
	emailChanges *mysqlstore.EmailChangeStore,
	passwords *mysqlstore.PasswordResetStore,
	outbox *mysqlstore.OutboxStore,
	audits *mysqlstore.AuditStore,
	invalidator *mysqlstore.AuthInvalidator,
	codec *mail.SecretCodec,
	blobs blob.Store,
	resetExpiry time.Duration,
) *Users {
	if resetExpiry <= 0 {
		resetExpiry = time.Hour
	}
	return &Users{
		access:       accessStore,
		accounts:     accounts,
		profiles:     profiles,
		emailChanges: emailChanges,
		passwords:    passwords,
		outbox:       outbox,
		audits:       audits,
		invalidator:  invalidator,
		txManager:    mysqlstore.NewTxManager(db),
		lastAdmin:    NewLastAdminGuard(accounts, accessStore),
		codec:        codec,
		blobs:        blobs,
		resetExpiry:  resetExpiry,
	}
}

// List trả danh sách người dùng đã áp dụng filter và pagination của quản trị viên.
func (u *Users) List(ctx context.Context, query UserListQuery) (UserPage, error) {
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PerPage < 1 || query.PerPage > 100 {
		query.PerPage = 20
	}
	now := time.Now().UTC()
	rows, total, err := u.access.ListUsers(ctx, mysqlstore.AccessUserFilter{
		Username: query.Username,
		Email:    query.Email,
		Status:   query.Status,
		Role:     query.Role,
		SortBy:   query.SortBy,
		SortDesc: !strings.EqualFold(query.SortOrder, "asc"),
		Limit:    query.PerPage,
		Offset:   (query.Page - 1) * query.PerPage,
		Now:      now,
	})
	if err != nil {
		return UserPage{}, err
	}
	userIDs := make([]uint64, 0, len(rows))
	for _, row := range rows {
		userIDs = append(userIDs, row.ID)
	}
	roleNames, err := u.access.RoleNamesByUserIDs(ctx, userIDs)
	if err != nil {
		return UserPage{}, err
	}
	users := make([]User, 0, len(rows))
	for _, row := range rows {
		roles := roleNames[row.ID]
		if roles == nil {
			roles = []string{}
		}
		users = append(users, u.userFromRow(row, roles))
	}
	return UserPage{
		Users:      users,
		Page:       query.Page,
		PerPage:    query.PerPage,
		Total:      total,
		TotalPages: (int(total) + query.PerPage - 1) / query.PerPage,
	}, nil
}

// Get trả chi tiết quản trị của một user hoặc business error khi không tồn tại.
func (u *Users) Get(ctx context.Context, userID uint64) (*User, error) {
	row, err := u.access.FindUser(ctx, userID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, apperror.ErrNotFound
	}
	roles, err := u.access.RoleNamesByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if roles == nil {
		roles = []string{}
	}
	user := u.userFromRow(*row, roles)
	return &user, nil
}

// Update sửa hồ sơ quản trị được phép mà không thay đổi account-state field.
func (u *Users) Update(ctx context.Context, command UpdateUserCommand) error {
	var dateOfBirth *time.Time
	if command.DateOfBirth != nil {
		value, err := time.Parse("2006-01-02", *command.DateOfBirth)
		if err != nil {
			return apperror.ErrInvalidDateFormat
		}
		dateOfBirth = &value
	}

	var newAvatarKey *string
	if command.AvatarObjectKey != nil {
		rawKey := strings.TrimSpace(*command.AvatarObjectKey)
		if rawKey != "" {
			canonicalKey, err := blob.CanonicalAvatarKey(rawKey)
			if err != nil || len(rawKey) > 255 {
				return apperror.ErrValidationError.WithMessage("Khóa ảnh đại diện không hợp lệ")
			}
			newAvatarKey = &canonicalKey
		}
	}

	now := time.Now().UTC()
	var oldAvatarKey *string
	err := u.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		snapshot, err := u.lastAdmin.Lock(txCtx, command.ActorID, command.TargetID)
		if err != nil {
			return err
		}
		if err := snapshot.RequireAdminForAdminTarget(
			"Không thể cập nhật tài khoản admin",
		); err != nil {
			return err
		}
		state, err := snapshot.Target.State()
		if err != nil {
			return err
		}

		email := snapshot.Target.Email
		emailChanged := command.Email != nil && *command.Email != email
		verificationChanged := command.EmailVerified != nil &&
			*command.EmailVerified != state.EmailVerified
		if emailChanged {
			email = *command.Email
		}
		if emailChanged || verificationChanged {
			verified := state.EmailVerified
			if emailChanged {
				verified = false
			}
			if command.EmailVerified != nil {
				verified = *command.EmailVerified
			}
			state.SetEmailVerification(verified)
		}
		if err := snapshot.EnsureTargetRemainsAvailable(
			snapshot.TargetIsAdmin && usableAdmin(state),
		); err != nil {
			return err
		}

		if command.FullName != nil || command.Phone != nil || dateOfBirth != nil {
			if err := u.profiles.UpdateMutable(
				txCtx,
				command.TargetID,
				command.FullName,
				command.Phone,
				dateOfBirth,
			); err != nil {
				return err
			}
		}
		if command.AvatarObjectKey != nil {
			var err error
			oldAvatarKey, err = u.profiles.SwapAvatar(
				txCtx,
				command.TargetID,
				newAvatarKey,
			)
			if err != nil {
				return err
			}
		}
		if emailChanged || verificationChanged {
			if emailChanged {
				if err := u.accounts.UpdateEmail(
					txCtx,
					command.TargetID,
					email,
					state,
					now,
				); err != nil {
					if errorsIsConflict(err) {
						return apperror.ErrConflict.WithMessage(
							"Email đã được sử dụng bởi người dùng khác",
						)
					}
					return err
				}
			} else if err := u.accounts.UpdateState(
				txCtx,
				command.TargetID,
				state,
				now,
			); err != nil {
				return err
			}
			if emailChanged {
				if err := u.cancelSecurityWorkflows(txCtx, command.TargetID, now); err != nil {
					return err
				}
			}
			if err := u.invalidator.DeleteSessions(txCtx, command.TargetID); err != nil {
				return err
			}
		}
		return writeAudit(
			txCtx,
			u.audits,
			command.ActorID,
			"ADMIN_UPDATE_USER",
			"users",
			strconv.FormatUint(command.TargetID, 10),
			command.Metadata,
		)
	})
	if err != nil {
		return err
	}

	if oldAvatarKey != nil && *oldAvatarKey != "" {
		if newAvatarKey == nil || *oldAvatarKey != *newAvatarKey {
			_ = u.blobs.Delete(ctx, *oldAvatarKey)
		}
	}
	return nil
}

// ChangeStatus thay đổi trạng thái trong access use case.
func (u *Users) ChangeStatus(ctx context.Context, command ChangeStatusCommand) error {
	if command.ActorID == command.TargetID {
		return apperror.ErrBadRequest.WithMessage(
			"Không thể tự khóa tài khoản của chính mình",
		)
	}
	now := time.Now().UTC()
	return u.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		snapshot, err := u.lastAdmin.Lock(txCtx, command.ActorID, command.TargetID)
		if err != nil {
			return err
		}
		if err := snapshot.RequireAdminForAdminTarget(
			"Không thể thay đổi trạng thái tài khoản admin",
		); err != nil {
			return err
		}
		state, err := snapshot.Target.State()
		if err != nil {
			return err
		}
		if err := state.SetAdministrativeStatus(
			accountstate.PublicStatus(command.Status),
			now,
		); err != nil {
			return err
		}
		if err := snapshot.EnsureTargetRemainsAvailable(
			snapshot.TargetIsAdmin && usableAdmin(state),
		); err != nil {
			return err
		}
		if err := u.accounts.UpdateState(
			txCtx,
			command.TargetID,
			state,
			now,
		); err != nil {
			return err
		}
		if err := u.invalidator.DeleteSessions(txCtx, command.TargetID); err != nil {
			return err
		}
		return writeAudit(
			txCtx,
			u.audits,
			command.ActorID,
			"ADMIN_CHANGE_STATUS",
			"users",
			strconv.FormatUint(command.TargetID, 10),
			command.Metadata,
		)
	})
}

// RequestPasswordReset tạo reset challenge và outbox event cho user do admin chọn.
func (u *Users) RequestPasswordReset(
	ctx context.Context,
	command ResetPasswordCommand,
) error {
	token, err := hash.GenerateResetToken()
	if err != nil {
		return fmt.Errorf("generate admin password reset token: %w", err)
	}
	tokenHash := hash.SHA256(token)
	now := time.Now().UTC()
	return u.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		snapshot, err := u.lastAdmin.Lock(txCtx, command.ActorID, command.TargetID)
		if err != nil {
			return err
		}
		if err := snapshot.RequireAdminForAdminTarget(
			"Không thể đặt lại mật khẩu tài khoản admin",
		); err != nil {
			return err
		}
		state, err := snapshot.Target.State()
		if err != nil {
			return err
		}
		state.InvalidateAuth()
		if err := u.accounts.UpdateState(
			txCtx,
			command.TargetID,
			state,
			now,
		); err != nil {
			return err
		}
		if err := u.invalidator.DeleteSessions(txCtx, command.TargetID); err != nil {
			return err
		}
		if err := u.cancelSecurityWorkflows(txCtx, command.TargetID, now); err != nil {
			return err
		}
		tokenID, err := u.passwords.Create(
			txCtx,
			command.TargetID,
			tokenHash,
			state.AuthVersion,
			now.Add(u.resetExpiry),
		)
		if err != nil {
			return err
		}
		payload, err := u.codec.Seal(mail.SecretMessage{
			To:     snapshot.Target.Email,
			Secret: token,
		})
		if err != nil {
			return err
		}
		if err := u.outbox.Enqueue(txCtx, &mysqlstore.OutboxEvent{
			EventType:      mail.PasswordResetRequested,
			AggregateType:  "password_reset_token",
			AggregateID:    strconv.FormatUint(tokenID, 10),
			Payload:        payload,
			IdempotencyKey: "password-reset:" + strconv.FormatUint(tokenID, 10),
			MaxAttempts:    10,
			AvailableAt:    now,
		}); err != nil {
			return err
		}
		return writeAudit(
			txCtx,
			u.audits,
			command.ActorID,
			"ADMIN_RESET_PASSWORD",
			"users",
			strconv.FormatUint(command.TargetID, 10),
			command.Metadata,
		)
	})
}

// Notify ghi durable admin-notification event thay vì gửi mail trong request goroutine.
func (u *Users) Notify(ctx context.Context, command NotifyUserCommand) error {
	if strings.ContainsAny(command.Subject, "\r\n") {
		return apperror.ErrValidationError.WithMessage(
			"Tiêu đề thông báo không hợp lệ",
		)
	}
	now := time.Now().UTC()
	eventID := uuid.NewString()
	return u.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := u.accounts.FindByIDForUpdate(txCtx, command.TargetID)
		if err != nil {
			return err
		}
		if account == nil {
			return apperror.ErrNotFound
		}
		state, err := account.State()
		if err != nil {
			return err
		}
		if state.EffectiveStatus(now) != accountstate.PublicActive {
			return apperror.ErrBadRequest.WithMessage(
				"Chỉ có thể gửi thông báo cho tài khoản đang hoạt động",
			)
		}
		payload, err := u.codec.SealAdminNotification(mail.AdminNotification{
			To:      account.Email,
			Subject: command.Subject,
			Message: command.Message,
		})
		if err != nil {
			return err
		}
		if err := u.outbox.Enqueue(txCtx, &mysqlstore.OutboxEvent{
			EventType:      mail.AdminNotificationRequested,
			AggregateType:  "user",
			AggregateID:    strconv.FormatUint(command.TargetID, 10),
			Payload:        payload,
			IdempotencyKey: "admin-notification:" + eventID,
			MaxAttempts:    10,
			AvailableAt:    now,
		}); err != nil {
			return err
		}
		return writeAudit(
			txCtx,
			u.audits,
			command.ActorID,
			"ADMIN_NOTIFY_USER",
			"users",
			strconv.FormatUint(command.TargetID, 10),
			command.Metadata,
		)
	})
}

// cancelSecurityWorkflows hủy challenge và outbox security còn pending trong transaction.
func (u *Users) cancelSecurityWorkflows(
	ctx context.Context,
	userID uint64,
	now time.Time,
) error {
	if err := u.outbox.CancelPendingEmailChange(ctx, userID, now); err != nil {
		return err
	}
	if err := u.emailChanges.CancelActiveByUser(ctx, userID, now); err != nil {
		return err
	}
	if err := u.outbox.CancelPendingPasswordReset(ctx, userID, now); err != nil {
		return err
	}
	return u.passwords.InvalidateActiveByUser(ctx, userID, now)
}

// userFromRow ánh xạ persistence row và canonical state sang domain user.
func (u *Users) userFromRow(row mysqlstore.AccessUser, roles []string) User {
	var avatarURL *string
	if row.AvatarObjectKey != nil {
		value := u.blobs.URL(*row.AvatarObjectKey)
		if value != "" {
			avatarURL = &value
		}
	}
	return User{
		ID:            row.ID,
		Username:      row.Username,
		Email:         row.Email,
		FullName:      row.FullName,
		Phone:         row.Phone,
		Status:        row.Status,
		EmailVerified: row.EmailVerified,
		DateOfBirth:   row.DateOfBirth,
		AvatarURL:     avatarURL,
		Roles:         roles,
		CreatedAt:     row.CreatedAt,
	}
}

// errorsIsConflict nhận diện business conflict mà admin mutation được phép trả công khai.
func errorsIsConflict(err error) bool {
	appError, ok := err.(*apperror.AppError)
	return ok && appError.Code == apperror.ErrConflict.Code
}

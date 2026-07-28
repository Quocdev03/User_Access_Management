package account

import (
	"context"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	accessapp "github.com/quocdev03/user-access-management/internal/access"
	"github.com/quocdev03/user-access-management/internal/blob"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

type ProfileView struct {
	ID            uint64
	AvatarURL     *string
	Username      string
	Email         string
	FullName      string
	Phone         string
	Status        string
	DateOfBirth   string
	EmailVerified bool
	CreatedAt     time.Time
	Roles         []string
}

type UpdateProfileCommand struct {
	FullName    *string
	Phone       *string
	DateOfBirth *string
	IPAddress   string
	UserAgent   string
}

type Profile struct {
	accounts  *mysqlstore.AccountStore
	profiles  *mysqlstore.ProfileStore
	roles     *mysqlstore.RoleStore
	audits    *mysqlstore.AuditStore
	blobs     blob.Store
	txManager *mysqlstore.TxManager
}

func NewProfile(
	db *sqlx.DB,
	accounts *mysqlstore.AccountStore,
	profiles *mysqlstore.ProfileStore,
	roles *mysqlstore.RoleStore,
	audits *mysqlstore.AuditStore,
	blobs blob.Store,
) *Profile {
	return &Profile{
		accounts:  accounts,
		profiles:  profiles,
		roles:     roles,
		audits:    audits,
		blobs:     blobs,
		txManager: mysqlstore.NewTxManager(db),
	}
}

func (p *Profile) Get(ctx context.Context, userID uint64) (ProfileView, error) {
	account, err := p.accounts.FindByID(ctx, userID)
	if err != nil {
		return ProfileView{}, err
	}
	if account == nil {
		return ProfileView{}, apperror.ErrNotFound
	}
	profile, err := p.profiles.FindByUserID(ctx, userID)
	if err != nil {
		return ProfileView{}, err
	}
	if profile == nil {
		return ProfileView{}, apperror.ErrNotFound
	}
	roles, err := p.roles.NamesByUserID(ctx, userID)
	if err != nil {
		return ProfileView{}, err
	}
	if len(roles) == 0 {
		roles = []string{accessapp.RoleUser}
	}
	state, err := account.State()
	if err != nil {
		return ProfileView{}, err
	}
	var avatarURL *string
	if profile.AvatarObjectKey != nil && *profile.AvatarObjectKey != "" {
		value := p.blobs.URL(*profile.AvatarObjectKey)
		avatarURL = &value
	}
	return ProfileView{
		ID:            account.ID,
		AvatarURL:     avatarURL,
		Username:      account.Username,
		Email:         account.Email,
		FullName:      profile.FullName,
		Phone:         profile.Phone,
		Status:        string(state.EffectiveStatus(time.Now().UTC())),
		DateOfBirth:   profile.DateOfBirth.Format("2006-01-02"),
		EmailVerified: state.EmailVerified,
		CreatedAt:     account.CreatedAt,
		Roles:         roles,
	}, nil
}

func (p *Profile) Update(
	ctx context.Context,
	userID uint64,
	command UpdateProfileCommand,
) error {
	var dateOfBirth *time.Time
	if command.DateOfBirth != nil {
		parsed, err := time.Parse("2006-01-02", *command.DateOfBirth)
		if err != nil {
			return apperror.ErrInvalidDateFormat
		}
		dateOfBirth = &parsed
	}

	return p.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		if err := p.profiles.UpdateMutable(
			txCtx,
			userID,
			command.FullName,
			command.Phone,
			dateOfBirth,
		); err != nil {
			return err
		}
		resource := "profile"
		resourceID := strconv.FormatUint(userID, 10)
		ipAddress := command.IPAddress
		userAgent := command.UserAgent
		return p.audits.Create(txCtx, &mysqlstore.AuditLog{
			UserID:     &userID,
			Action:     "UPDATE_PROFILE",
			Resource:   &resource,
			ResourceID: &resourceID,
			IPAddress:  &ipAddress,
			UserAgent:  &userAgent,
			Status:     "success",
		})
	})
}

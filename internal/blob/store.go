package blob

import (
	"context"
	"io"

	"github.com/quocdev03/user-access-management/internal/config"
)

type Store interface {
	Put(ctx context.Context, key string, content io.Reader) error
	Delete(ctx context.Context, key string) error
	URL(key string) string
}

type VerifiedStore interface {
	Store
	VerifySHA256(ctx context.Context, key string, expectedHex string) error
}

func NewStore(ctx context.Context, cfg config.BlobConfig) (Store, error) {
	if cfg.Provider == "s3" {
		return NewS3Store(ctx, cfg)
	}
	return NewLocalStore(cfg.LocalRoot)
}

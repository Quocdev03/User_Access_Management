package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/quocdev03/user-access-management/internal/config"
)

type s3API interface {
	PutObject(
		context.Context,
		*s3.PutObjectInput,
		...func(*s3.Options),
	) (*s3.PutObjectOutput, error)
	DeleteObject(
		context.Context,
		*s3.DeleteObjectInput,
		...func(*s3.Options),
	) (*s3.DeleteObjectOutput, error)
	GetObject(
		context.Context,
		*s3.GetObjectInput,
		...func(*s3.Options),
	) (*s3.GetObjectOutput, error)
}

type S3Store struct {
	client        s3API
	bucket        string
	publicBaseURL string
}

func NewS3Store(ctx context.Context, cfg config.BlobConfig) (*S3Store, error) {
	publicURL, err := url.Parse(cfg.PublicBaseURL)
	if err != nil ||
		publicURL.Scheme != "https" ||
		publicURL.Host == "" {
		return nil, fmt.Errorf("S3 public base URL must be an absolute HTTPS URL")
	}
	loadOptions := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
	}
	if cfg.AccessKeyID != "" {
		loadOptions = append(
			loadOptions,
			awsconfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(
					cfg.AccessKeyID,
					cfg.SecretAccessKey,
					"",
				),
			),
		)
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load S3 configuration: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(options *s3.Options) {
		options.UsePathStyle = cfg.ForcePathStyle
		if cfg.Endpoint != "" {
			options.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	})
	return &S3Store{
		client:        client,
		bucket:        cfg.Bucket,
		publicBaseURL: cfg.PublicBaseURL,
	}, nil
}

func (s *S3Store) Put(
	ctx context.Context,
	key string,
	content io.Reader,
) error {
	objectKey, err := normalizeS3Key(key)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("read S3 blob content: %w", err)
	}
	checksum := sha256.Sum256(body)
	contentLength := int64(len(body))
	if _, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:            aws.String(s.bucket),
		Key:               aws.String(objectKey),
		Body:              bytes.NewReader(body),
		ContentLength:     aws.Int64(contentLength),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		ChecksumSHA256:    aws.String(base64.StdEncoding.EncodeToString(checksum[:])),
	}); err != nil {
		return fmt.Errorf("put S3 blob: %w", err)
	}
	return nil
}

func (s *S3Store) Delete(ctx context.Context, key string) error {
	objectKey, err := normalizeS3Key(key)
	if err != nil {
		return err
	}
	if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(objectKey),
	}); err != nil {
		return fmt.Errorf("delete S3 blob: %w", err)
	}
	return nil
}

func (s *S3Store) URL(key string) string {
	switch {
	case key == "":
		return ""
	case strings.HasPrefix(key, "https://"):
		return key
	case strings.HasPrefix(key, "http://"):
		return ""
	}
	objectKey, err := normalizeS3Key(key)
	if err != nil {
		return ""
	}
	segments := strings.Split(objectKey, "/")
	for index := range segments {
		segments[index] = url.PathEscape(segments[index])
	}
	return s.publicBaseURL + "/" + strings.Join(segments, "/")
}

func (s *S3Store) VerifySHA256(
	ctx context.Context,
	key string,
	expectedHex string,
) error {
	objectKey, err := normalizeS3Key(key)
	if err != nil {
		return err
	}
	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket:       aws.String(s.bucket),
		Key:          aws.String(objectKey),
		ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil {
		return fmt.Errorf("read S3 blob for verification: %w", err)
	}
	defer output.Body.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, output.Body); err != nil {
		return fmt.Errorf("verify S3 blob checksum: %w", err)
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if subtle.ConstantTimeCompare(
		[]byte(strings.ToLower(actual)),
		[]byte(strings.ToLower(expectedHex)),
	) != 1 {
		return fmt.Errorf("S3 blob checksum mismatch")
	}
	return nil
}

func normalizeS3Key(key string) (string, error) {
	normalized := strings.TrimSpace(strings.TrimPrefix(key, "/uploads/"))
	if normalized == "" ||
		strings.HasPrefix(normalized, "/") ||
		strings.HasPrefix(normalized, "http://") ||
		strings.HasPrefix(normalized, "https://") {
		return "", fmt.Errorf("invalid S3 blob key")
	}
	clean := path.Clean(normalized)
	if clean == "." ||
		clean == ".." ||
		strings.HasPrefix(clean, "../") ||
		!strings.HasPrefix(clean, "avatars/") {
		return "", fmt.Errorf("invalid S3 blob key")
	}
	return clean, nil
}

func CanonicalAvatarKey(key string) (string, error) {
	return normalizeS3Key(key)
}

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
	"net/http"
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

// File này lưu, đọc và xóa blob qua S3-compatible API.

// s3API định nghĩa interface trừu tượng hóa các phương thức S3 SDK được sử dụng.
type s3API interface {
	// PutObject ghi object bằng S3 client và tôn trọng context cancellation.
	PutObject(
		context.Context,
		*s3.PutObjectInput,
		...func(*s3.Options),
	) (*s3.PutObjectOutput, error)
	// DeleteObject xóa object bằng S3 client và tôn trọng context cancellation.
	DeleteObject(
		context.Context,
		*s3.DeleteObjectInput,
		...func(*s3.Options),
	) (*s3.DeleteObjectOutput, error)
	// GetObject mở response body của object để caller đọc và đóng.
	GetObject(
		context.Context,
		*s3.GetObjectInput,
		...func(*s3.Options),
	) (*s3.GetObjectOutput, error)
}

// S3Store triển khai Store lưu trữ và quản lý đối tượng trên dịch vụ tương thích AWS S3.
type S3Store struct {
	client        s3API
	bucket        string
	publicBaseURL string
}

// NewS3Store khởi tạo S3Store với các dependency được cung cấp.
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

// Put ghi object vào bucket sau khi chuẩn hóa key và nhận diện content type.
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
	contentType := detectBlobContentType(objectKey, body)
	if _, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:             aws.String(s.bucket),
		Key:                aws.String(objectKey),
		Body:               bytes.NewReader(body),
		ContentLength:      aws.Int64(contentLength),
		ContentType:        aws.String(contentType),
		ContentDisposition: aws.String("inline"),
		ChecksumAlgorithm:  types.ChecksumAlgorithmSha256,
		ChecksumSHA256:     aws.String(base64.StdEncoding.EncodeToString(checksum[:])),
	}); err != nil {
		return fmt.Errorf("put S3 blob: %w", err)
	}
	return nil
}

// detectBlobContentType xác định MIME type của file dựa trên byte content hoặc phần mở rộng.
func detectBlobContentType(key string, data []byte) string {
	detected := http.DetectContentType(data)
	if detected == "application/octet-stream" || detected == "text/plain; charset=utf-8" {
		ext := strings.ToLower(path.Ext(key))
		switch ext {
		case ".png":
			return "image/png"
		case ".jpg", ".jpeg":
			return "image/jpeg"
		case ".webp":
			return "image/webp"
		case ".gif":
			return "image/gif"
		case ".svg":
			return "image/svg+xml"
		}
	}
	return detected
}

// Delete xóa object khỏi bucket và giữ idempotency của blob boundary.
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

// URL tạo địa chỉ đọc object theo endpoint và bucket đã cấu hình.
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

// VerifySHA256 đọc object và so sánh digest constant-time với checksum mong đợi.
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

// normalizeS3Key từ chối object key tuyệt đối hoặc chứa path traversal.
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

// CanonicalAvatarKey tạo object key ổn định theo user ID và phần mở rộng đã kiểm tra.
func CanonicalAvatarKey(key string) (string, error) {
	return normalizeS3Key(key)
}

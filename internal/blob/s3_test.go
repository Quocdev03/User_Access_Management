package blob

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// File này kiểm chứng hành vi s 3 và các trường hợp lỗi liên quan.

// TestS3StorePutProvidesSHA256AndCanonicalKey kiểm chứng kịch bản S3StorePutProvidesSHA256AndCanonicalKey.
func TestS3StorePutProvidesSHA256AndCanonicalKey(t *testing.T) {
	client := &fakeS3Client{}
	store := &S3Store{
		client:        client,
		bucket:        "avatars-bucket",
		publicBaseURL: "https://cdn.example.com",
	}

	if err := store.Put(
		context.Background(),
		"/uploads/avatars/user image.png",
		strings.NewReader("avatar"),
	); err != nil {
		t.Fatalf("Put(): %v", err)
	}

	if got := *client.put.Bucket; got != "avatars-bucket" {
		t.Fatalf("bucket = %q", got)
	}
	if got := *client.put.Key; got != "avatars/user image.png" {
		t.Fatalf("key = %q", got)
	}
	if client.put.ChecksumSHA256 == nil {
		t.Fatal("SHA-256 checksum missing")
	}
	decoded, err := base64.StdEncoding.DecodeString(*client.put.ChecksumSHA256)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("checksum = %q, err = %v", *client.put.ChecksumSHA256, err)
	}
	if client.put.ContentType == nil || *client.put.ContentType != "image/png" {
		t.Fatalf("ContentType = %v, expected image/png", client.put.ContentType)
	}
	if client.put.ContentDisposition == nil || *client.put.ContentDisposition != "inline" {
		t.Fatalf("ContentDisposition = %v, expected inline", client.put.ContentDisposition)
	}
	if got := store.URL("avatars/user image.png"); got != "https://cdn.example.com/avatars/user%20image.png" {
		t.Fatalf("URL() = %q", got)
	}
}

// TestS3StoreRejectsUnsafeKeysAndChecksumMismatch kiểm chứng kịch bản S3StoreRejectsUnsafeKeysAndChecksumMismatch.
func TestS3StoreRejectsUnsafeKeysAndChecksumMismatch(t *testing.T) {
	client := &fakeS3Client{body: []byte("different")}
	store := &S3Store{
		client:        client,
		bucket:        "avatars-bucket",
		publicBaseURL: "https://cdn.example.com",
	}

	if err := store.Put(
		context.Background(),
		"../secret",
		strings.NewReader("avatar"),
	); err == nil {
		t.Fatal("Put accepted traversal key")
	}
	if err := store.VerifySHA256(
		context.Background(),
		"avatars/user.png",
		strings.Repeat("0", 64),
	); err == nil {
		t.Fatal("VerifySHA256 accepted mismatched content")
	}
}

// fakeS3Client là mock client triển khai s3API phục vụ unit test S3 store.
type fakeS3Client struct {
	put  *s3.PutObjectInput
	body []byte
}

// PutObject ghi object qua blob storage boundary.
func (c *fakeS3Client) PutObject(
	_ context.Context,
	input *s3.PutObjectInput,
	_ ...func(*s3.Options),
) (*s3.PutObjectOutput, error) {
	c.put = input
	return &s3.PutObjectOutput{}, nil
}

// DeleteObject xóa object qua blob storage boundary.
func (c *fakeS3Client) DeleteObject(
	context.Context,
	*s3.DeleteObjectInput,
	...func(*s3.Options),
) (*s3.DeleteObjectOutput, error) {
	return &s3.DeleteObjectOutput{}, nil
}

// GetObject lấy object qua blob storage boundary.
func (c *fakeS3Client) GetObject(
	context.Context,
	*s3.GetObjectInput,
	...func(*s3.Options),
) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(c.body)),
	}, nil
}

package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	recoveryCodeRandomBytes = 10
	totpPeriodSeconds       = 30
)

type MFASecretCodec struct {
	activeVersion string
	keys          map[string][]byte
}

func NewMFASecretCodec(
	activeVersion string,
	keys map[string][]byte,
) (*MFASecretCodec, error) {
	if activeVersion == "" {
		return nil, fmt.Errorf("active MFA key version is required")
	}
	keyCopies := make(map[string][]byte, len(keys))
	for version, key := range keys {
		if version == "" || len(key) != 32 {
			return nil, fmt.Errorf("MFA key %q must contain 32 bytes", version)
		}
		keyCopies[version] = append([]byte(nil), key...)
	}
	if _, ok := keyCopies[activeVersion]; !ok {
		return nil, fmt.Errorf("active MFA key %q is unavailable", activeVersion)
	}
	return &MFASecretCodec{
		activeVersion: activeVersion,
		keys:          keyCopies,
	}, nil
}

func (c *MFASecretCodec) Encrypt(userID uint64, secret string) ([]byte, string, error) {
	block, err := aes.NewCipher(c.keys[c.activeVersion])
	if err != nil {
		return nil, "", fmt.Errorf("initialize MFA cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", fmt.Errorf("initialize MFA GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", fmt.Errorf("generate MFA nonce: %w", err)
	}
	ciphertext := make(
		[]byte,
		0,
		len(nonce)+len(secret)+gcm.Overhead(),
	)
	ciphertext = append(ciphertext, nonce...)
	ciphertext = gcm.Seal(
		ciphertext,
		nonce,
		[]byte(secret),
		mfaSecretAAD(userID, c.activeVersion),
	)
	return ciphertext, c.activeVersion, nil
}

func (c *MFASecretCodec) Decrypt(
	userID uint64,
	keyVersion string,
	ciphertext []byte,
) (string, error) {
	key, ok := c.keys[keyVersion]
	if !ok {
		return "", fmt.Errorf("MFA key version %q is unavailable", keyVersion)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("initialize MFA cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("initialize MFA GCM: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize()+gcm.Overhead() {
		return "", fmt.Errorf("MFA ciphertext is truncated")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	plaintext, err := gcm.Open(
		nil,
		nonce,
		ciphertext[gcm.NonceSize():],
		mfaSecretAAD(userID, keyVersion),
	)
	if err != nil {
		return "", fmt.Errorf("decrypt MFA secret: %w", err)
	}
	return string(plaintext), nil
}

func generateRecoveryCodes(count int) ([]string, [][]byte, error) {
	codes := make([]string, 0, count)
	hashes := make([][]byte, 0, count)
	for range count {
		random := make([]byte, recoveryCodeRandomBytes)
		if _, err := io.ReadFull(rand.Reader, random); err != nil {
			return nil, nil, fmt.Errorf("generate MFA recovery code: %w", err)
		}
		encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random)
		code := strings.Join([]string{
			encoded[0:4],
			encoded[4:8],
			encoded[8:12],
			encoded[12:16],
		}, "-")
		sum := sha256.Sum256([]byte(encoded))
		codes = append(codes, code)
		hashes = append(hashes, sum[:])
	}
	return codes, hashes, nil
}

func recoveryCodeHash(code string) ([]byte, bool) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(normalized) != 16 {
		return nil, false
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(normalized); err != nil {
		return nil, false
	}
	sum := sha256.Sum256([]byte(normalized))
	return sum[:], true
}

func generateTOTPEnrollment(issuer string, accountName string) (
	secret string,
	enrollmentURI string,
	err error,
) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      totpPeriodSeconds,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		// HMAC-SHA1 is the interoperable RFC 6238 profile used by mainstream
		// authenticator applications; it is not used as a collision hash.
		Algorithm: otp.AlgorithmSHA1,
		Rand:      rand.Reader,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate TOTP enrollment: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

func validateTOTPCode(
	secret string,
	code string,
	now time.Time,
) (uint64, bool, error) {
	if !isSixDigitCode(code) {
		return 0, false, nil
	}
	opts := totp.ValidateOpts{
		Period:    totpPeriodSeconds,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	for _, offset := range []int{0, -1, 1} {
		candidateTime := now.UTC().Add(
			time.Duration(offset*totpPeriodSeconds) * time.Second,
		)
		valid, err := totp.ValidateCustom(code, secret, candidateTime, opts)
		if err != nil {
			return 0, false, fmt.Errorf("validate TOTP code: %w", err)
		}
		if valid {
			return uint64(candidateTime.Unix() / totpPeriodSeconds), true, nil
		}
	}
	return 0, false, nil
}

func isSixDigitCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func mfaSecretAAD(userID uint64, keyVersion string) []byte {
	return []byte(
		"uam:mfa:totp:" + strconv.FormatUint(userID, 10) + ":" + keyVersion,
	)
}

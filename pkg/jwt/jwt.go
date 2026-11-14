// Package jwt ký và xác minh access token của UAM.
package jwt

import (
	"errors"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// File này ký access token và xác minh claim bằng secret được cấu hình.

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token is expired")
)

// Claims chứa các payload dữ liệu của JWT bao gồm UserID, AuthVersion, Roles và RegisteredClaims.
type Claims struct {
	UserID      uint64   `json:"user_id"`
	AuthVersion uint64   `json:"auth_version"`
	Type        string   `json:"type"`
	Roles       []string `json:"roles"`
	golangjwt.RegisteredClaims
}

// GenerateToken tạo token và từ chối token có chữ ký hoặc claim không hợp lệ.
func GenerateToken(userID uint64, roles []string, tokenType string, expiry time.Duration, secret string) (string, string, error) {
	return GenerateTokenWithAuthVersion(userID, 0, roles, tokenType, expiry, secret)
}

// GenerateTokenWithAuthVersion ký access token có auth_version để middleware phát hiện credential mutation.
func GenerateTokenWithAuthVersion(
	userID uint64,
	authVersion uint64,
	roles []string,
	tokenType string,
	expiry time.Duration,
	secret string,
) (string, string, error) {
	jti := uuid.New().String()
	now := time.Now()
	claims := Claims{
		UserID:      userID,
		AuthVersion: authVersion,
		Type:        tokenType,
		Roles:       roles,
		RegisteredClaims: golangjwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: golangjwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  golangjwt.NewNumericDate(now),
			NotBefore: golangjwt.NewNumericDate(now),
		},
	}

	token := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", "", err
	}

	return tokenString, jti, nil
}

// ParseToken phân tích token và từ chối token có chữ ký hoặc claim không hợp lệ.
func ParseToken(tokenStr string, secret string) (*Claims, error) {
	token, err := golangjwt.ParseWithClaims(tokenStr, &Claims{}, func(token *golangjwt.Token) (interface{}, error) {
		if token.Method.Alg() != golangjwt.SigningMethodHS256.Alg() {
			return nil, ErrInvalidToken
		}
		return []byte(secret), nil
	}, golangjwt.WithValidMethods([]string{golangjwt.SigningMethodHS256.Alg()}))

	if err != nil {
		if errors.Is(err, golangjwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ParseTokenAllowExpired phân tích token và trích xuất claims kể cả khi token đã hết hạn,
// nhưng vẫn từ chối nếu chữ ký hoặc thuật toán không hợp lệ.
func ParseTokenAllowExpired(tokenStr string, secret string) (*Claims, bool, error) {
	token, err := golangjwt.ParseWithClaims(tokenStr, &Claims{}, func(token *golangjwt.Token) (interface{}, error) {
		if token.Method.Alg() != golangjwt.SigningMethodHS256.Alg() {
			return nil, ErrInvalidToken
		}
		return []byte(secret), nil
	}, golangjwt.WithValidMethods([]string{golangjwt.SigningMethodHS256.Alg()}))

	if err != nil {
		if errors.Is(err, golangjwt.ErrTokenExpired) {
			if token != nil {
				if claims, ok := token.Claims.(*Claims); ok && claims != nil {
					return claims, true, nil
				}
			}
			return nil, true, ErrExpiredToken
		}
		return nil, false, ErrInvalidToken
	}

	if token == nil {
		return nil, false, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, false, ErrInvalidToken
	}

	return claims, false, nil
}

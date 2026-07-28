package auth

import (
	"bytes"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestMFASecretCodecRoundTripRotationAndTamperDetection(t *testing.T) {
	oldKey := bytes.Repeat([]byte{1}, 32)
	newKey := bytes.Repeat([]byte{2}, 32)
	oldCodec, err := NewMFASecretCodec("v1", map[string][]byte{"v1": oldKey})
	if err != nil {
		t.Fatalf("NewMFASecretCodec(v1): %v", err)
	}
	ciphertext, version, err := oldCodec.Encrypt(42, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Encrypt(): %v", err)
	}
	if version != "v1" || bytes.Contains(ciphertext, []byte("JBSWY3DPEHPK3PXP")) {
		t.Fatalf("ciphertext/version = %q/%x", version, ciphertext)
	}

	rotatedCodec, err := NewMFASecretCodec("v2", map[string][]byte{
		"v1": oldKey,
		"v2": newKey,
	})
	if err != nil {
		t.Fatalf("NewMFASecretCodec(v2): %v", err)
	}
	plaintext, err := rotatedCodec.Decrypt(42, version, ciphertext)
	if err != nil || plaintext != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Decrypt() = %q, %v", plaintext, err)
	}
	if _, err := rotatedCodec.Decrypt(43, version, ciphertext); err == nil {
		t.Fatal("Decrypt() accepted ciphertext for another user")
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 1
	if _, err := rotatedCodec.Decrypt(42, version, tampered); err == nil {
		t.Fatal("Decrypt() accepted tampered ciphertext")
	}
}

func TestValidateTOTPCodeAllowsOneStepAndReturnsMatchedStep(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_710_000_000, 0).UTC()
	opts := totp.ValidateOpts{
		Period:    totpPeriodSeconds,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	for _, offset := range []int{-1, 0, 1} {
		at := now.Add(time.Duration(offset*totpPeriodSeconds) * time.Second)
		code, err := totp.GenerateCodeCustom(secret, at, opts)
		if err != nil {
			t.Fatalf("GenerateCodeCustom(%d): %v", offset, err)
		}
		step, valid, err := validateTOTPCode(secret, code, now)
		if err != nil || !valid {
			t.Fatalf("validate offset %d = step %d valid %v err %v", offset, step, valid, err)
		}
		wantStep := uint64(at.Unix() / totpPeriodSeconds)
		if step != wantStep {
			t.Fatalf("step = %d, want %d", step, wantStep)
		}
	}
	twoStepsOld, err := totp.GenerateCodeCustom(
		secret,
		now.Add(-2*totpPeriodSeconds*time.Second),
		opts,
	)
	if err != nil {
		t.Fatalf("GenerateCodeCustom(two steps): %v", err)
	}
	if _, valid, err := validateTOTPCode(secret, twoStepsOld, now); err != nil || valid {
		t.Fatalf("two-step code valid=%v err=%v", valid, err)
	}
	if _, valid, err := validateTOTPCode(secret, "12ab", now); err != nil || valid {
		t.Fatalf("malformed code valid=%v err=%v", valid, err)
	}
}

func TestRecoveryCodesAreRandomNormalizedAndHashable(t *testing.T) {
	codes, hashes, err := generateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("generateRecoveryCodes(): %v", err)
	}
	if len(codes) != 10 || len(hashes) != 10 {
		t.Fatalf("codes/hashes lengths = %d/%d", len(codes), len(hashes))
	}
	seen := map[string]struct{}{}
	for index, code := range codes {
		if len(code) != 19 {
			t.Fatalf("code %q length = %d", code, len(code))
		}
		if _, duplicate := seen[code]; duplicate {
			t.Fatalf("duplicate recovery code %q", code)
		}
		seen[code] = struct{}{}
		normalizedHash, valid := recoveryCodeHash(code)
		if !valid || !bytes.Equal(normalizedHash, hashes[index]) {
			t.Fatalf("recoveryCodeHash(%q) valid=%v", code, valid)
		}
	}
	if _, valid := recoveryCodeHash("invalid!"); valid {
		t.Fatal("recoveryCodeHash() accepted malformed code")
	}
}

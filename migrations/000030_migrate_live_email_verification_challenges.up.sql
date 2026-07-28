-- Preserve verification codes issued before the target auth cutover.
-- The plaintext OTP was already delivered; only its existing hash and attempt
-- state are copied. Expired/consumed rows remain historical legacy data.
INSERT INTO `verification_challenges` (
    `request_id`,
    `user_id`,
    `purpose`,
    `subject`,
    `secret_hash`,
    `attempts`,
    `consumed_at`,
    `expires_at`,
    `created_at`,
    `updated_at`
)
SELECT
    CONCAT('legacy-', LPAD(LOWER(HEX(o.id)), 29, '0')),
    o.user_id,
    'email_verification',
    u.email,
    o.code,
    o.attempts,
    NULL,
    o.expires_at,
    o.created_at,
    CURRENT_TIMESTAMP
FROM `otp_codes` o
INNER JOIN `users` u ON u.id = o.user_id
WHERE o.type = 'email_verification'
  AND o.is_used = FALSE
  AND o.expires_at > CURRENT_TIMESTAMP
ON DUPLICATE KEY UPDATE request_id = VALUES(request_id);

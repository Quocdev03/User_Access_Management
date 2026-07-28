UPDATE `users`
SET
    `lifecycle_state` = COALESCE(
        `lifecycle_state`,
        CASE
            WHEN `status` = 'active' THEN 'active'
            WHEN `status` = 'locked' AND `email_verified` = 1 THEN 'active'
            WHEN `email_verified` = 0 THEN 'pending_verification'
            ELSE 'disabled'
        END
    ),
    `administrative_locked_at` = CASE
        WHEN `administrative_locked_at` IS NOT NULL THEN `administrative_locked_at`
        WHEN `status` = 'locked' AND `locked_until` IS NULL THEN `updated_at`
        ELSE NULL
    END,
    `login_locked_until` = CASE
        WHEN `login_locked_until` IS NOT NULL THEN `login_locked_until`
        WHEN `status` = 'locked' AND `locked_until` IS NOT NULL THEN `locked_until`
        ELSE NULL
    END,
    `password_change_required` = COALESCE(
        `password_change_required`,
        `must_change_password`
    ),
    `auth_version` = COALESCE(`auth_version`, 0);

INSERT INTO `user_profiles` (
    `user_id`,
    `full_name`,
    `phone`,
    `date_of_birth`,
    `avatar_object_key`,
    `created_at`,
    `updated_at`
)
SELECT
    `id`,
    `full_name`,
    `phone`,
    `date_of_birth`,
    `avatar_url`,
    `created_at`,
    `updated_at`
FROM `users`
ON DUPLICATE KEY UPDATE `user_id` = VALUES(`user_id`);

DELETE FROM `sessions`
WHERE `jti` IS NULL OR TRIM(`jti`) = '';

UPDATE `sessions`
SET
    `access_jti` = COALESCE(`access_jti`, `jti`),
    `current_refresh_hash` = COALESCE(
        `current_refresh_hash`,
        `refresh_token_hash`
    ),
    `client_profile_id` = COALESCE(`client_profile_id`, `device_id`),
    `updated_at` = COALESCE(`updated_at`, `created_at`);

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

UPDATE `password_reset_tokens` p
INNER JOIN `users` u ON u.id = p.user_id
SET
    p.auth_version = u.auth_version,
    p.is_used = TRUE,
    p.consumed_at = COALESCE(p.consumed_at, CURRENT_TIMESTAMP)
WHERE p.auth_version IS NULL;

CREATE TEMPORARY TABLE `uam_contract_consistency_check` (
    `check_name` VARCHAR(64) NOT NULL,
    `mismatch_count` BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (`check_name`),
    CONSTRAINT `chk_uam_contract_zero_mismatch`
        CHECK (`mismatch_count` = 0)
) ENGINE=InnoDB;

INSERT INTO `uam_contract_consistency_check`
    (`check_name`, `mismatch_count`)
SELECT
    'missing_account_state',
    COUNT(*)
FROM `users`
WHERE `lifecycle_state` IS NULL
   OR `password_change_required` IS NULL
   OR `auth_version` IS NULL;

INSERT INTO `uam_contract_consistency_check`
    (`check_name`, `mismatch_count`)
SELECT
    'missing_profile',
    COUNT(*)
FROM `users` u
LEFT JOIN `user_profiles` p ON p.user_id = u.id
WHERE p.user_id IS NULL;

INSERT INTO `uam_contract_consistency_check`
    (`check_name`, `mismatch_count`)
SELECT
    'profile_projection',
    COUNT(*)
FROM `users` u
INNER JOIN `user_profiles` p ON p.user_id = u.id
WHERE NOT (u.full_name <=> p.full_name)
   OR NOT (u.phone <=> p.phone)
   OR NOT (u.date_of_birth <=> p.date_of_birth)
   OR NOT (u.avatar_url <=> p.avatar_object_key);

INSERT INTO `uam_contract_consistency_check`
    (`check_name`, `mismatch_count`)
SELECT
    'account_projection',
    COUNT(*)
FROM `users`
WHERE NOT (
        `status` <=>
        CASE
            WHEN `administrative_locked_at` IS NOT NULL
                OR `login_locked_until` IS NOT NULL
                THEN 'locked'
            WHEN `lifecycle_state` = 'active' THEN 'active'
            ELSE 'inactive'
        END
    )
   OR NOT (
        `locked_until` <=>
        CASE
            WHEN `administrative_locked_at` IS NULL
                THEN `login_locked_until`
            ELSE NULL
        END
    )
   OR `must_change_password` <> `password_change_required`;

INSERT INTO `uam_contract_consistency_check`
    (`check_name`, `mismatch_count`)
SELECT
    'session_canonical',
    COUNT(*)
FROM `sessions`
WHERE `access_jti` IS NULL
   OR TRIM(`access_jti`) = ''
   OR `current_refresh_hash` IS NULL
   OR TRIM(`current_refresh_hash`) = '';

INSERT INTO `uam_contract_consistency_check`
    (`check_name`, `mismatch_count`)
SELECT
    'session_projection',
    COUNT(*)
FROM `sessions`
WHERE NOT (`jti` <=> `access_jti`)
   OR NOT (`refresh_token_hash` <=> `current_refresh_hash`)
   OR NOT (`device_id` <=> `client_profile_id`);

INSERT INTO `uam_contract_consistency_check`
    (`check_name`, `mismatch_count`)
SELECT
    'permission_semantics',
    COUNT(*)
FROM (
    SELECT `resource`, `action`
    FROM `permissions`
    GROUP BY `resource`, `action`
    HAVING COUNT(*) > 1
) duplicates;

INSERT INTO `uam_contract_consistency_check`
    (`check_name`, `mismatch_count`)
SELECT
    'system_role_marker',
    COUNT(*)
FROM `roles`
WHERE (`name` IN ('admin', 'moderator', 'user') AND `is_system` <> 1)
   OR (`name` NOT IN ('admin', 'moderator', 'user') AND `is_system` <> 0);

INSERT INTO `uam_contract_consistency_check`
    (`check_name`, `mismatch_count`)
SELECT
    'active_email_otp',
    COUNT(*)
FROM `otp_codes` o
INNER JOIN `users` u ON u.id = o.user_id
LEFT JOIN `verification_challenges` v
    ON v.request_id = CONCAT(
        'legacy-',
        LPAD(LOWER(HEX(o.id)), 29, '0')
    )
    AND v.purpose = 'email_verification'
    AND v.subject = u.email
    AND v.secret_hash = o.code
WHERE o.type = 'email_verification'
  AND o.is_used = FALSE
  AND o.expires_at > CURRENT_TIMESTAMP
  AND v.id IS NULL;

INSERT INTO `uam_contract_consistency_check`
    (`check_name`, `mismatch_count`)
SELECT
    'active_non_email_otp',
    COUNT(*)
FROM `otp_codes`
WHERE `type` <> 'email_verification'
  AND `is_used` = FALSE
  AND `expires_at` > CURRENT_TIMESTAMP;

INSERT INTO `uam_contract_consistency_check`
    (`check_name`, `mismatch_count`)
SELECT
    'reset_auth_version',
    COUNT(*)
FROM `password_reset_tokens`
WHERE `auth_version` IS NULL;

DROP TEMPORARY TABLE `uam_contract_consistency_check`;

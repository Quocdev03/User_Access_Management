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

ALTER TABLE `users`
    DROP INDEX `idx_users_status_created`,
    DROP INDEX `idx_users_email_verified_status`,
    ADD INDEX `idx_users_lifecycle_created`
        (`lifecycle_state`, `created_at`),
    ADD INDEX `idx_users_email_verified_lifecycle`
        (`email_verified`, `lifecycle_state`),
    MODIFY COLUMN `lifecycle_state`
        ENUM('pending_verification', 'active', 'disabled') NOT NULL,
    MODIFY COLUMN `password_change_required`
        TINYINT(1) NOT NULL,
    MODIFY COLUMN `auth_version`
        BIGINT UNSIGNED NOT NULL,
    DROP COLUMN `full_name`,
    DROP COLUMN `phone`,
    DROP COLUMN `avatar_url`,
    DROP COLUMN `date_of_birth`,
    DROP COLUMN `status`,
    DROP COLUMN `locked_until`,
    DROP COLUMN `must_change_password`;

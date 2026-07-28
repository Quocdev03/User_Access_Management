ALTER TABLE `sessions`
    DROP FOREIGN KEY `fk_sessions_device_id`,
    DROP INDEX `uk_sessions_token_hash`,
    DROP INDEX `uk_sessions_refresh_token_hash`,
    DROP INDEX `idx_sessions_jti`,
    MODIFY COLUMN `access_jti`
        VARCHAR(36) NOT NULL,
    MODIFY COLUMN `current_refresh_hash`
        VARCHAR(255) NOT NULL,
    DROP COLUMN `token_hash`,
    DROP COLUMN `refresh_token_hash`,
    DROP COLUMN `jti`,
    DROP COLUMN `device_id`;

ALTER TABLE `password_reset_tokens`
    MODIFY COLUMN `auth_version`
        BIGINT UNSIGNED NOT NULL,
    DROP COLUMN `is_used`;

DROP TABLE `otp_codes`;

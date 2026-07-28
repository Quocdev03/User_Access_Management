ALTER TABLE `sessions`
    ADD COLUMN `access_jti`
        VARCHAR(36) NULL DEFAULT NULL AFTER `jti`,
    ADD COLUMN `current_refresh_hash`
        VARCHAR(255) NULL DEFAULT NULL AFTER `refresh_token_hash`,
    ADD COLUMN `client_profile_id`
        BIGINT UNSIGNED NULL DEFAULT NULL AFTER `device_id`,
    ADD COLUMN `revoked_at`
        DATETIME NULL DEFAULT NULL AFTER `expires_at`,
    ADD COLUMN `updated_at`
        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER `created_at`,
    ADD UNIQUE KEY `uk_sessions_current_refresh_hash` (`current_refresh_hash`),
    ADD INDEX `idx_sessions_access_jti` (`access_jti`),
    ADD INDEX `idx_sessions_revoked_expires` (`revoked_at`, `expires_at`),
    ADD CONSTRAINT `fk_sessions_client_profile_id`
        FOREIGN KEY (`client_profile_id`) REFERENCES `devices` (`id`)
        ON DELETE SET NULL ON UPDATE CASCADE;

CREATE TABLE `refresh_token_history` (
    `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `token_hash` VARCHAR(255) NOT NULL,
    `session_id` BIGINT UNSIGNED NULL DEFAULT NULL,
    `user_id`    BIGINT UNSIGNED NOT NULL,
    `rotated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `expires_at` DATETIME NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_refresh_token_history_token_hash` (`token_hash`),
    INDEX `idx_refresh_token_history_session_id` (`session_id`),
    INDEX `idx_refresh_token_history_user_expires` (`user_id`, `expires_at`),
    CONSTRAINT `fk_refresh_token_history_session_id`
        FOREIGN KEY (`session_id`) REFERENCES `sessions` (`id`)
        ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT `fk_refresh_token_history_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

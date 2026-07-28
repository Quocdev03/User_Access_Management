CREATE TABLE `email_change_requests` (
    `id`                    CHAR(36) NOT NULL,
    `user_id`               BIGINT UNSIGNED NOT NULL,
    `old_email`             VARCHAR(255) NOT NULL,
    `new_email`             VARCHAR(255) NOT NULL,
    `auth_version_snapshot` BIGINT UNSIGNED NOT NULL,
    `state`                 VARCHAR(32) NOT NULL,
    `expires_at`            DATETIME NOT NULL,
    `completed_at`          DATETIME NULL DEFAULT NULL,
    `cancelled_at`          DATETIME NULL DEFAULT NULL,
    `created_at`            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    INDEX `idx_email_change_requests_user_state` (`user_id`, `state`),
    INDEX `idx_email_change_requests_expires_at` (`expires_at`),
    CONSTRAINT `fk_email_change_requests_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `verification_challenges` (
    `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `request_id`              CHAR(36) NOT NULL,
    `user_id`                 BIGINT UNSIGNED NOT NULL,
    `email_change_request_id` CHAR(36) NULL DEFAULT NULL,
    `purpose`                 VARCHAR(50) NOT NULL,
    `subject`                 VARCHAR(255) NOT NULL,
    `secret_hash`             VARCHAR(255) NOT NULL,
    `attempts`                INT UNSIGNED NOT NULL DEFAULT 0,
    `consumed_at`             DATETIME NULL DEFAULT NULL,
    `expires_at`              DATETIME NOT NULL,
    `created_at`              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_verification_challenges_request` (`request_id`, `purpose`, `subject`),
    INDEX `idx_verification_challenges_user_purpose`
        (`user_id`, `purpose`, `consumed_at`, `expires_at`),
    INDEX `idx_verification_challenges_expires_at` (`expires_at`),
    CONSTRAINT `fk_verification_challenges_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_verification_challenges_email_change_request_id`
        FOREIGN KEY (`email_change_request_id`) REFERENCES `email_change_requests` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE `password_reset_tokens`
    ADD COLUMN `auth_version`
        BIGINT UNSIGNED NULL DEFAULT NULL AFTER `token_hash`,
    ADD COLUMN `consumed_at`
        DATETIME NULL DEFAULT NULL AFTER `is_used`;

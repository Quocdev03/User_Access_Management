CREATE TABLE `user_totp` (
    `user_id`           BIGINT UNSIGNED NOT NULL,
    `secret_ciphertext` VARBINARY(255) NOT NULL,
    `key_version`       VARCHAR(32) NOT NULL,
    `last_used_step`    BIGINT UNSIGNED NULL DEFAULT NULL,
    `confirmed_at`      DATETIME NULL DEFAULT NULL,
    `enabled_at`        DATETIME NULL DEFAULT NULL,
    `created_at`        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (`user_id`),
    CONSTRAINT `fk_user_totp_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `user_totp_recovery_codes` (
    `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`    BIGINT UNSIGNED NOT NULL,
    `code_hash`  BINARY(32) NOT NULL,
    `used_at`    DATETIME NULL DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_user_totp_recovery_user_hash` (`user_id`, `code_hash`),
    INDEX `idx_user_totp_recovery_user_unused` (`user_id`, `used_at`),
    CONSTRAINT `fk_user_totp_recovery_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

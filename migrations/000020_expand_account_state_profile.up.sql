ALTER TABLE `users`
    ADD COLUMN `lifecycle_state`
        ENUM('pending_verification', 'active', 'disabled') NULL AFTER `status`,
    ADD COLUMN `administrative_locked_at`
        DATETIME NULL DEFAULT NULL AFTER `email_verified`,
    ADD COLUMN `login_locked_until`
        DATETIME NULL DEFAULT NULL AFTER `administrative_locked_at`,
    ADD COLUMN `password_change_required`
        TINYINT(1) NULL DEFAULT NULL AFTER `must_change_password`,
    ADD COLUMN `auth_version`
        BIGINT UNSIGNED NULL DEFAULT NULL AFTER `password_change_required`;

CREATE TABLE `user_profiles` (
    `user_id`           BIGINT UNSIGNED NOT NULL,
    `full_name`         VARCHAR(100) NOT NULL,
    `phone`             VARCHAR(20) NOT NULL,
    `date_of_birth`     DATE NOT NULL,
    `avatar_object_key` VARCHAR(500) NULL DEFAULT NULL,
    `created_at`        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (`user_id`),
    CONSTRAINT `fk_user_profiles_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

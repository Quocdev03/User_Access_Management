CREATE TABLE `outbox_events` (
    `id`               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `event_type`       VARCHAR(100) NOT NULL,
    `aggregate_type`   VARCHAR(100) NOT NULL,
    `aggregate_id`     VARCHAR(100) NOT NULL,
    `payload`          JSON NOT NULL,
    `idempotency_key`  VARCHAR(255) NOT NULL,
    `attempts`         INT UNSIGNED NOT NULL DEFAULT 0,
    `max_attempts`     INT UNSIGNED NOT NULL DEFAULT 10,
    `available_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `claimed_at`       DATETIME NULL DEFAULT NULL,
    `claimed_by`       VARCHAR(100) NULL DEFAULT NULL,
    `delivered_at`     DATETIME NULL DEFAULT NULL,
    `dead_lettered_at` DATETIME NULL DEFAULT NULL,
    `last_error`       TEXT NULL DEFAULT NULL,
    `created_at`       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_outbox_events_idempotency_key` (`idempotency_key`),
    INDEX `idx_outbox_events_delivery`
        (`delivered_at`, `dead_lettered_at`, `available_at`),
    INDEX `idx_outbox_events_claim`
        (`claimed_at`, `available_at`, `id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

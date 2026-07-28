ALTER TABLE `roles`
    ADD COLUMN `is_system`
        TINYINT(1) NULL DEFAULT NULL AFTER `description`,
    ADD INDEX `idx_roles_is_system` (`is_system`);

ALTER TABLE `permissions`
    ADD INDEX `idx_permissions_resource_action` (`resource`, `action`);

ALTER TABLE `audit_logs`
    DROP FOREIGN KEY `fk_audit_logs_user_id`;

ALTER TABLE `audit_logs`
    ADD CONSTRAINT `fk_audit_logs_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE SET NULL ON UPDATE CASCADE;

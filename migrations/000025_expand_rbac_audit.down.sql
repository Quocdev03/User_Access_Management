ALTER TABLE `audit_logs`
    DROP FOREIGN KEY `fk_audit_logs_user_id`;

ALTER TABLE `audit_logs`
    ADD CONSTRAINT `fk_audit_logs_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `permissions`
    DROP INDEX `idx_permissions_resource_action`;

ALTER TABLE `roles`
    DROP INDEX `idx_roles_is_system`,
    DROP COLUMN `is_system`;

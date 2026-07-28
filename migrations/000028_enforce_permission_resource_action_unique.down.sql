ALTER TABLE `permissions`
    DROP INDEX `uk_permissions_resource_action`,
    ADD INDEX `idx_permissions_resource_action` (`resource`, `action`);

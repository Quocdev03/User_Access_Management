ALTER TABLE `permissions`
    DROP INDEX `idx_permissions_resource_action`,
    ADD UNIQUE KEY `uk_permissions_resource_action` (`resource`, `action`);

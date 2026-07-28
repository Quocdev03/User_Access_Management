ALTER TABLE `devices`
    DROP INDEX `uk_devices_user_os_browser`;

ALTER TABLE `devices`
    MODIFY COLUMN `os` VARCHAR(50) NULL DEFAULT NULL,
    MODIFY COLUMN `browser` VARCHAR(50) NULL DEFAULT NULL;

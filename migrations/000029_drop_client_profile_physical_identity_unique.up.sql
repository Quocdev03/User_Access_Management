-- OS/browser families describe an observed client profile, not a physical device.
-- Keep existing rows and allow distinct user-agent observations for the same families.
ALTER TABLE `devices`
    DROP INDEX `uk_devices_user_os_browser`;

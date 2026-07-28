-- Normalize os/browser, dedupe devices, UNIQUE (user_id, os, browser).

UPDATE `devices`
SET
    `os` = COALESCE(`os`, ''),
    `browser` = COALESCE(`browser`, '');

ALTER TABLE `devices`
    MODIFY COLUMN `os` VARCHAR(50) NOT NULL DEFAULT '',
    MODIFY COLUMN `browser` VARCHAR(50) NOT NULL DEFAULT '';

-- Detach sessions pointing at devices that will be removed as duplicates.
UPDATE `sessions` s
INNER JOIN `devices` d ON s.device_id = d.id
INNER JOIN (
    SELECT user_id, os, browser, MAX(id) AS keep_id
    FROM devices
    GROUP BY user_id, os, browser
    HAVING COUNT(*) > 1
) k ON d.user_id = k.user_id AND d.os = k.os AND d.browser = k.browser
SET s.device_id = NULL
WHERE d.id <> k.keep_id;

-- Keep newest id per (user_id, os, browser); delete older duplicates.
DELETE d FROM `devices` d
INNER JOIN (
    SELECT user_id, os, browser, MAX(id) AS keep_id
    FROM devices
    GROUP BY user_id, os, browser
    HAVING COUNT(*) > 1
) k ON d.user_id = k.user_id AND d.os = k.os AND d.browser = k.browser
WHERE d.id <> k.keep_id;

ALTER TABLE `devices`
    ADD UNIQUE KEY `uk_devices_user_os_browser` (`user_id`, `os`, `browser`);

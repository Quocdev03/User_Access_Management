UPDATE `roles`
SET `is_system` = CASE
    WHEN `name` IN ('admin', 'moderator', 'user') THEN 1
    ELSE 0
END
WHERE `is_system` IS NULL;

CREATE TEMPORARY TABLE `uam_permission_uniqueness_check` (
    `resource` VARCHAR(50) NOT NULL,
    `action`   VARCHAR(50) NOT NULL,
    PRIMARY KEY (`resource`, `action`)
) ENGINE=InnoDB;

INSERT INTO `uam_permission_uniqueness_check` (`resource`, `action`)
SELECT `resource`, `action`
FROM `permissions`;

DROP TEMPORARY TABLE `uam_permission_uniqueness_check`;

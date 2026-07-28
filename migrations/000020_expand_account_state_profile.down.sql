DROP TABLE IF EXISTS `user_profiles`;

ALTER TABLE `users`
    DROP COLUMN `auth_version`,
    DROP COLUMN `password_change_required`,
    DROP COLUMN `login_locked_until`,
    DROP COLUMN `administrative_locked_at`,
    DROP COLUMN `lifecycle_state`;

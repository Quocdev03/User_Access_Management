ALTER TABLE `password_reset_tokens`
    DROP COLUMN `consumed_at`,
    DROP COLUMN `auth_version`;

DROP TABLE IF EXISTS `verification_challenges`;
DROP TABLE IF EXISTS `email_change_requests`;

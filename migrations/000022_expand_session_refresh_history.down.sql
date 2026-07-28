DROP TABLE IF EXISTS `refresh_token_history`;

ALTER TABLE `sessions`
    DROP FOREIGN KEY `fk_sessions_client_profile_id`,
    DROP INDEX `idx_sessions_revoked_expires`,
    DROP INDEX `idx_sessions_access_jti`,
    DROP INDEX `uk_sessions_current_refresh_hash`,
    DROP COLUMN `updated_at`,
    DROP COLUMN `revoked_at`,
    DROP COLUMN `client_profile_id`,
    DROP COLUMN `current_refresh_hash`,
    DROP COLUMN `access_jti`;

DELETE FROM `sessions`
WHERE `jti` IS NULL OR TRIM(`jti`) = '';

UPDATE `sessions`
SET
    `access_jti` = COALESCE(`access_jti`, `jti`),
    `current_refresh_hash` = COALESCE(
        `current_refresh_hash`,
        `refresh_token_hash`
    ),
    `client_profile_id` = COALESCE(`client_profile_id`, `device_id`),
    `updated_at` = COALESCE(`updated_at`, `created_at`);

UPDATE `users`
SET `auth_version` = COALESCE(`auth_version`, 0);

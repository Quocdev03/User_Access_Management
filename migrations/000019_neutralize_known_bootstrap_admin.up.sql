-- Remove the historical bootstrap account only while its identity and known
-- password hash are unchanged. Audit rows are retained and anonymized because
-- the current audit_logs foreign key uses ON DELETE RESTRICT.
SET @uam_known_bootstrap_user_id := (
    SELECT `id`
    FROM `users`
    WHERE `username` = 'admin_local'
      AND `email` = 'admin@localhost.local'
      AND `password_hash` = '$2a$10$tIgJSlVfv1hNKvcNZFpjK.HaE.YAhR3nFT0RUO.PoXWD1wJ9HBuFe'
    LIMIT 1
);

UPDATE `audit_logs`
SET `user_id` = NULL
WHERE `user_id` = @uam_known_bootstrap_user_id;

DELETE FROM `users`
WHERE `id` = @uam_known_bootstrap_user_id;

SET @uam_known_bootstrap_user_id := NULL;

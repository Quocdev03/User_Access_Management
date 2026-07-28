-- Bootstrap admin: buộc force-change sau mọi môi trường đã seed 000012.
-- Password seed LocalDev@ChangeMe1 không được dùng lâu dài trên production.
UPDATE `users`
SET `must_change_password` = TRUE
WHERE `email` = 'admin@localhost.local';

-- Irreversible contract migration: legacy session projections, OTP rows and
-- reset-token flags have no runtime owner. Production rollback requires a new
-- forward migration.
SELECT 1;

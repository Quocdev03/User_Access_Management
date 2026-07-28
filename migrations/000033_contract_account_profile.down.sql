-- Irreversible contract migration: removed profile/state columns no longer
-- contain authoritative data. Production rollback must use a forward-fix
-- migration and must not reconstruct stale mirrors.
SELECT 1;

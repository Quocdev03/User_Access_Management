-- Irreversible without merging or deleting client-profile observations created
-- after the unique key was removed. Production rollback keeps the preserved rows.
SELECT 1;

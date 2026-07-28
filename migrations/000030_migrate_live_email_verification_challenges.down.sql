-- Irreversible without deleting verification activity that may have happened
-- after cutover. A rollback keeps the preserved challenge rows.
SELECT 1;

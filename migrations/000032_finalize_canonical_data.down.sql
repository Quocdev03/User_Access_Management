-- Forward-only data finalization. Canonical writes after cutover cannot be
-- distinguished from copied values, and invalidated legacy reset tokens must
-- not be reactivated. Rollback requires a new forward migration.
SELECT 1;

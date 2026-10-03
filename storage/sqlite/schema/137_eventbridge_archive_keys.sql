-- Archive-owned migration progress survives restart. Existing payloads and their
-- archive start at generation zero, preserving their current encryption binding.
ALTER TABLE eventbridge_archives ADD COLUMN key_version BLOB NOT NULL DEFAULT X'0000000000000000' CHECK(length(key_version)=8);
ALTER TABLE eventbridge_archives ADD COLUMN migration_due_seconds INTEGER;
ALTER TABLE eventbridge_archives ADD COLUMN migration_due_nanos INTEGER NOT NULL DEFAULT 0;
ALTER TABLE eventbridge_archives ADD COLUMN previous_key_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE eventbridge_archives ADD COLUMN previous_kms_key_identifier TEXT NOT NULL DEFAULT '';
ALTER TABLE eventbridge_archive_entries ADD COLUMN key_version BLOB NOT NULL DEFAULT X'0000000000000000' CHECK(length(key_version)=8);
ALTER TABLE eventbridge_archive_entries ADD COLUMN rule_context BOOLEAN NOT NULL DEFAULT 1 CHECK(rule_context IN (0,1));
CREATE INDEX eventbridge_archive_migration_due ON eventbridge_archives(migration_due_seconds,migration_due_nanos,id) WHERE migration_due_seconds IS NOT NULL;
CREATE INDEX eventbridge_archive_migration_entries ON eventbridge_archive_entries(archive_id,key_version,id);

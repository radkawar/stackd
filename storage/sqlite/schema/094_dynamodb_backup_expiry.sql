ALTER TABLE dynamodb_backups ADD COLUMN backup_type TEXT NOT NULL DEFAULT 'USER';
ALTER TABLE dynamodb_backups ADD COLUMN backup_expires_at TIMESTAMP;
CREATE INDEX dynamodb_backups_expiry ON dynamodb_backups(backup_expires_at) WHERE backup_expires_at IS NOT NULL;

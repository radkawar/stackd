ALTER TABLE s3_buckets ADD COLUMN object_lock_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE s3_buckets ADD COLUMN default_retention_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_buckets ADD COLUMN default_retention_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE s3_buckets ADD COLUMN default_retention_years INTEGER NOT NULL DEFAULT 0;
ALTER TABLE s3_buckets ADD COLUMN default_event_hold_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE s3_buckets ADD COLUMN default_event_hold_years INTEGER NOT NULL DEFAULT 0;

ALTER TABLE s3_object_versions ADD COLUMN retention_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_object_versions ADD COLUMN retain_until TIMESTAMP;
ALTER TABLE s3_object_versions ADD COLUMN retention_modified TIMESTAMP;
ALTER TABLE s3_object_versions ADD COLUMN event_hold TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_object_versions ADD COLUMN event_hold_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE s3_object_versions ADD COLUMN event_hold_years INTEGER NOT NULL DEFAULT 0;
ALTER TABLE s3_object_versions ADD COLUMN legal_hold TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_object_versions ADD COLUMN legal_hold_modified TIMESTAMP;

ALTER TABLE s3_multipart_uploads ADD COLUMN retention_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_multipart_uploads ADD COLUMN retain_until TIMESTAMP;
ALTER TABLE s3_multipart_uploads ADD COLUMN retention_modified TIMESTAMP;
ALTER TABLE s3_multipart_uploads ADD COLUMN event_hold TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_multipart_uploads ADD COLUMN event_hold_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE s3_multipart_uploads ADD COLUMN event_hold_years INTEGER NOT NULL DEFAULT 0;
ALTER TABLE s3_multipart_uploads ADD COLUMN legal_hold TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_multipart_uploads ADD COLUMN legal_hold_modified TIMESTAMP;

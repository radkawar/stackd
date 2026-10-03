-- Logging controls and success-only native byte cursors share broker admission
-- and delivery transactions. Existing brokers start with logging disabled.
ALTER TABLE mq_brokers ADD COLUMN log_general BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE mq_brokers ADD COLUMN log_audit BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE mq_brokers ADD COLUMN log_pending_general BOOLEAN;
ALTER TABLE mq_brokers ADD COLUMN log_pending_audit BOOLEAN
    CHECK ((log_pending_general IS NULL) = (log_pending_audit IS NULL));
ALTER TABLE mq_brokers ADD COLUMN log_general_file_id TEXT NOT NULL DEFAULT '';
ALTER TABLE mq_brokers ADD COLUMN log_general_offset INTEGER NOT NULL DEFAULT 0 CHECK (log_general_offset >= 0);
ALTER TABLE mq_brokers ADD COLUMN log_audit_file_id TEXT NOT NULL DEFAULT '';
ALTER TABLE mq_brokers ADD COLUMN log_audit_offset INTEGER NOT NULL DEFAULT 0 CHECK (log_audit_offset >= 0);
ALTER TABLE mq_brokers ADD COLUMN log_delivery_error TEXT NOT NULL DEFAULT '';
ALTER TABLE mq_brokers ADD COLUMN log_due TIMESTAMP NOT NULL DEFAULT '0001-01-01T00:00:00+00:00';

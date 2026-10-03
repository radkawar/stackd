ALTER TABLE org_effective_policies ADD COLUMN validation_path TEXT NOT NULL DEFAULT '';
CREATE TABLE org_effective_policy_errors (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    position INTEGER NOT NULL,
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    path TEXT NOT NULL,
    PRIMARY KEY (partition,org_id,account_id,policy_type,position),
    FOREIGN KEY (partition,org_id,account_id,policy_type) REFERENCES org_effective_policies(partition,org_id,account_id,policy_type) ON DELETE CASCADE
);
CREATE TABLE org_effective_policy_error_sources (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    error_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    policy_id TEXT NOT NULL,
    PRIMARY KEY (partition,org_id,account_id,policy_type,error_position,position),
    FOREIGN KEY (partition,org_id,account_id,policy_type,error_position) REFERENCES org_effective_policy_errors(partition,org_id,account_id,policy_type,position) ON DELETE CASCADE
);
-- Prior versions did not validate the combined tag/backup policy. Their cached
-- content cannot serve as a last-known-valid document. Regenerate ordinary views
-- while preserving any already pending request origin and deadline.
UPDATE org_effective_policies SET content='', updated_at='0001-01-01 00:00:00+00:00',
    due=COALESCE(due,'0001-01-01 00:00:00+00:00')
WHERE policy_type IN ('BACKUP_POLICY','TAG_POLICY');

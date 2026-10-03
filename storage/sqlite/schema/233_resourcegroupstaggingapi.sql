-- Membership is independent of current tag values, which remain service-owned.
CREATE TABLE resourcegroupstaggingapi_memberships (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    service TEXT NOT NULL,
    arn TEXT NOT NULL,
    PRIMARY KEY (partition, account_id, region, service, arn)
);

-- One resumable latest-report intent per management-account/partition/Region.
-- caller_json is typed request authority, never credentials or resource tags.
CREATE TABLE resourcegroupstaggingapi_reports (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    version INTEGER NOT NULL,
    organization_id TEXT NOT NULL,
    bucket TEXT NOT NULL,
    object_key TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    completed_at INTEGER NOT NULL,
    due INTEGER NOT NULL,
    caller_json TEXT NOT NULL,
    PRIMARY KEY (partition, account_id, region)
);
CREATE INDEX resourcegroupstaggingapi_reports_due
ON resourcegroupstaggingapi_reports (due, partition, account_id, region)
WHERE status = 'RUNNING';

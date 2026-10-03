CREATE TABLE guardduty_publishing_destinations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 detector_id TEXT NOT NULL,
 id TEXT NOT NULL,
 arn TEXT NOT NULL UNIQUE,
 type TEXT NOT NULL,
 client_token TEXT NOT NULL,
 destination_arn TEXT NOT NULL,
 kms_key_arn TEXT NOT NULL,
 status TEXT NOT NULL,
 version INTEGER NOT NULL,
 created TIMESTAMP NOT NULL,
 updated TIMESTAMP NOT NULL,
 failure_started TIMESTAMP NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY(partition,account_id,region,detector_id,id),
 FOREIGN KEY(partition,account_id,region,detector_id) REFERENCES guardduty_detectors(partition,account_id,region,id) ON DELETE CASCADE
);
CREATE TABLE guardduty_publishing_destination_tags (
 arn TEXT NOT NULL REFERENCES guardduty_publishing_destinations(arn) ON DELETE CASCADE ON UPDATE CASCADE,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY(arn,tag_key)
);
CREATE TABLE guardduty_finding_exports (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 detector_id TEXT NOT NULL,
 destination_id TEXT NOT NULL,
 finding_id TEXT NOT NULL,
 id TEXT NOT NULL,
 object_key TEXT NOT NULL,
 parent_event_id TEXT NOT NULL,
 destination_version INTEGER NOT NULL,
 version INTEGER NOT NULL,
 created TIMESTAMP NOT NULL,
 due TIMESTAMP NOT NULL,
 last_published TIMESTAMP NOT NULL,
 payload BLOB,
 PRIMARY KEY(partition,account_id,region,detector_id,destination_id,finding_id),
 FOREIGN KEY(partition,account_id,region,detector_id,destination_id) REFERENCES guardduty_publishing_destinations(partition,account_id,region,detector_id,id) ON DELETE CASCADE,
 FOREIGN KEY(partition,account_id,region,detector_id,finding_id) REFERENCES guardduty_findings(partition,account_id,region,detector_id,id) ON DELETE CASCADE
);
CREATE INDEX guardduty_export_deadlines ON guardduty_finding_exports(partition,account_id,region,detector_id,destination_id,due,finding_id);

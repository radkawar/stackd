CREATE TABLE guardduty_ip_lists (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 detector_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 id TEXT NOT NULL,
 arn TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL,
 format TEXT NOT NULL,
 location TEXT NOT NULL,
 expected_bucket_owner TEXT NOT NULL,
 client_token TEXT NOT NULL,
 status TEXT NOT NULL,
 version INTEGER NOT NULL,
 due TIMESTAMP NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY(partition,account_id,region,detector_id,kind,id),
 FOREIGN KEY(partition,account_id,region,detector_id) REFERENCES guardduty_detectors(partition,account_id,region,id) ON DELETE CASCADE
);
CREATE TABLE guardduty_ip_list_tags (
 arn TEXT NOT NULL REFERENCES guardduty_ip_lists(arn) ON DELETE CASCADE,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY(arn,tag_key)
);
-- Immutable normalized snapshots use the scoped primary key for predecessor
-- lookup, so each event reads at most one interval per active list.
CREATE TABLE guardduty_ip_ranges (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 detector_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 id TEXT NOT NULL,
 first_ip INTEGER NOT NULL CHECK(first_ip BETWEEN 0 AND 4294967295),
 last_ip INTEGER NOT NULL CHECK(last_ip BETWEEN first_ip AND 4294967295),
 PRIMARY KEY(partition,account_id,region,detector_id,kind,id,first_ip),
 FOREIGN KEY(partition,account_id,region,detector_id,kind,id) REFERENCES guardduty_ip_lists(partition,account_id,region,detector_id,kind,id) ON DELETE CASCADE
) WITHOUT ROWID;

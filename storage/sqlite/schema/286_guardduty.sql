CREATE TABLE guardduty_detectors (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 arn TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL,
 frequency TEXT NOT NULL,
 service_role TEXT NOT NULL,
 client_token TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 updated TIMESTAMP NOT NULL,
 features_present BOOLEAN NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY(partition,account_id,region,id)
);
CREATE TABLE guardduty_detector_tags (
 arn TEXT NOT NULL REFERENCES guardduty_detectors(arn) ON DELETE CASCADE,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY(arn,tag_key)
);
CREATE TABLE guardduty_features (
 arn TEXT NOT NULL REFERENCES guardduty_detectors(arn) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 name TEXT NOT NULL,
 status TEXT NOT NULL,
 updated TIMESTAMP NOT NULL,
 additional_present BOOLEAN NOT NULL,
 PRIMARY KEY(arn,position)
);
CREATE TABLE guardduty_additional_features (
 arn TEXT NOT NULL,
 feature_position INTEGER NOT NULL,
 position INTEGER NOT NULL,
 name TEXT NOT NULL,
 status TEXT NOT NULL,
 updated TIMESTAMP NOT NULL,
 PRIMARY KEY(arn,feature_position,position),
 FOREIGN KEY(arn,feature_position) REFERENCES guardduty_features(arn,position) ON DELETE CASCADE
);
CREATE TABLE guardduty_findings (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 detector_id TEXT NOT NULL,
 id TEXT NOT NULL,
 sample_type TEXT NOT NULL,
 sample_revision TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 updated TIMESTAMP NOT NULL,
 count INTEGER NOT NULL,
 archived BOOLEAN NOT NULL,
 feedback TEXT NOT NULL,
 last_published TIMESTAMP NOT NULL,
 publish_due TIMESTAMP NOT NULL,
 suppressed BOOLEAN NOT NULL,
 PRIMARY KEY(partition,account_id,region,detector_id,id),
 FOREIGN KEY(partition,account_id,region,detector_id) REFERENCES guardduty_detectors(partition,account_id,region,id) ON DELETE CASCADE
);
CREATE TABLE guardduty_observations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 detector_id TEXT NOT NULL,
 id TEXT NOT NULL,
 type TEXT NOT NULL,
 title TEXT NOT NULL,
 description TEXT NOT NULL,
 severity REAL NOT NULL,
 event_id TEXT NOT NULL,
 access_key_id TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 user_name TEXT NOT NULL,
 user_type TEXT NOT NULL,
 api TEXT NOT NULL,
 service_name TEXT NOT NULL,
 source_ip TEXT NOT NULL,
 error_code TEXT NOT NULL,
 resource_type TEXT NOT NULL,
 resource_name TEXT NOT NULL,
 feature_name TEXT NOT NULL,
 PRIMARY KEY(partition,account_id,region,detector_id,id),
 FOREIGN KEY(partition,account_id,region,detector_id,id) REFERENCES guardduty_findings(partition,account_id,region,detector_id,id) ON DELETE CASCADE
);
CREATE TABLE guardduty_filters (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 detector_id TEXT NOT NULL,
 name TEXT NOT NULL,
 arn TEXT NOT NULL UNIQUE,
 action TEXT NOT NULL,
 description TEXT NOT NULL,
 client_token TEXT NOT NULL,
 description_set BOOLEAN NOT NULL,
 rank INTEGER NOT NULL,
 version INTEGER NOT NULL,
 created TIMESTAMP NOT NULL,
 updated TIMESTAMP NOT NULL,
 criteria_present BOOLEAN NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY(partition,account_id,region,detector_id,name),
 FOREIGN KEY(partition,account_id,region,detector_id) REFERENCES guardduty_detectors(partition,account_id,region,id) ON DELETE CASCADE
);
CREATE TABLE guardduty_filter_tags (
 arn TEXT NOT NULL REFERENCES guardduty_filters(arn) ON DELETE CASCADE,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY(arn,tag_key)
);
-- Presence flags retain nil versus explicitly empty SDK maps and lists.
CREATE TABLE guardduty_filter_conditions (
 arn TEXT NOT NULL REFERENCES guardduty_filters(arn) ON DELETE CASCADE,
 criterion TEXT NOT NULL,
 greater_than INTEGER,
 greater_than_or_equal INTEGER,
 gt INTEGER,
 gte INTEGER,
 less_than INTEGER,
 less_than_or_equal INTEGER,
 lt INTEGER,
 lte INTEGER,
 eq_present BOOLEAN NOT NULL,
 equals_present BOOLEAN NOT NULL,
 neq_present BOOLEAN NOT NULL,
 not_equals_present BOOLEAN NOT NULL,
 matches_present BOOLEAN NOT NULL,
 not_matches_present BOOLEAN NOT NULL,
 PRIMARY KEY(arn,criterion)
);
CREATE TABLE guardduty_filter_condition_values (
 arn TEXT NOT NULL,
 criterion TEXT NOT NULL,
 operator TEXT NOT NULL CHECK(operator IN ('eq','equals','neq','notEquals','matches','notMatches')),
 position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(arn,criterion,operator,position),
 FOREIGN KEY(arn,criterion) REFERENCES guardduty_filter_conditions(arn,criterion) ON DELETE CASCADE
);

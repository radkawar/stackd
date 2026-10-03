CREATE TABLE guardduty_observation_threat_lists (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 detector_id TEXT NOT NULL,
 id TEXT NOT NULL,
 position INTEGER NOT NULL,
 name TEXT NOT NULL,
 PRIMARY KEY(partition,account_id,region,detector_id,id,position),
 FOREIGN KEY(partition,account_id,region,detector_id,id) REFERENCES guardduty_observations(partition,account_id,region,detector_id,id) ON DELETE CASCADE
) WITHOUT ROWID;

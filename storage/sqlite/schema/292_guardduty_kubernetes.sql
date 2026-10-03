-- Findings reference immutable native evidence instead of duplicating its payload.
CREATE TABLE guardduty_observation_kubernetes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 detector_id TEXT NOT NULL,
 id TEXT NOT NULL,
 sequence INTEGER NOT NULL REFERENCES kubernetes_audit_events(sequence),
 PRIMARY KEY(partition,account_id,region,detector_id,id),
 FOREIGN KEY(partition,account_id,region,detector_id,id) REFERENCES guardduty_observations(partition,account_id,region,detector_id,id) ON DELETE CASCADE
) WITHOUT ROWID;

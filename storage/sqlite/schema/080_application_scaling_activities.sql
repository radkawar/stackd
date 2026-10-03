-- Activities outlive target and policy deletion. Accepted intent belongs to the
-- activity rather than a second mutable copy on the policy.
ALTER TABLE aas_policies ADD COLUMN pending_activity_id TEXT NOT NULL DEFAULT '';
ALTER TABLE aas_policies DROP COLUMN pending_scale_at;
ALTER TABLE aas_policies DROP COLUMN pending_scale_from;
ALTER TABLE aas_policies DROP COLUMN pending_scale_to;

CREATE TABLE aas_activities (
 activity_pk INTEGER PRIMARY KEY AUTOINCREMENT,
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 activity_id TEXT NOT NULL,
 namespace TEXT NOT NULL, resource_id TEXT NOT NULL, dimension TEXT NOT NULL,
 cause TEXT NOT NULL, description TEXT NOT NULL, details TEXT,
 start_time TIMESTAMP NOT NULL, end_time TIMESTAMP,
 status_code TEXT NOT NULL, status_message TEXT,
 policy_name TEXT NOT NULL, capacity_from INTEGER NOT NULL, capacity_to INTEGER NOT NULL,
 origin_event_id TEXT NOT NULL,
 UNIQUE(partition, account_id, region, activity_id)
);
CREATE INDEX aas_activities_history ON aas_activities(partition, account_id, region, namespace, start_time DESC, activity_pk DESC);
CREATE INDEX aas_activities_pending ON aas_activities(partition, account_id, region, namespace, resource_id, dimension)
 WHERE status_code IN ('Pending', 'InProgress');
CREATE INDEX aas_activities_queued ON aas_activities(start_time, activity_pk) WHERE status_code = 'Pending';
CREATE TABLE aas_activity_reasons (
 activity_pk INTEGER NOT NULL REFERENCES aas_activities(activity_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL, code TEXT NOT NULL,
 current_capacity INTEGER, min_capacity INTEGER, max_capacity INTEGER,
 PRIMARY KEY(activity_pk, position)
);

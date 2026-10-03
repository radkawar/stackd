CREATE TABLE kubernetes_audit_events (
 sequence INTEGER PRIMARY KEY REFERENCES kernel_events(sequence) ON DELETE CASCADE,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 cluster_arn TEXT NOT NULL,
 cluster_id TEXT NOT NULL,
 cluster_name TEXT NOT NULL,
 audit_id TEXT NOT NULL,
 stage TEXT NOT NULL,
 verb TEXT NOT NULL,
 request_uri TEXT NOT NULL,
 user_name TEXT NOT NULL,
 user_uid TEXT NOT NULL,
 actor_user_name TEXT NOT NULL,
 source_ip TEXT NOT NULL,
 namespace TEXT NOT NULL,
 resource TEXT NOT NULL,
 subresource TEXT NOT NULL,
 name TEXT NOT NULL,
 user_agent TEXT NOT NULL,
 api_version TEXT NOT NULL,
 response_code INTEGER NOT NULL,
 native_at TIMESTAMP NOT NULL,
 UNIQUE(partition,account_id,region,cluster_id,audit_id,stage)
);
CREATE TABLE kubernetes_audit_groups (
 sequence INTEGER NOT NULL REFERENCES kubernetes_audit_events(sequence) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 name TEXT NOT NULL,
 PRIMARY KEY(sequence,position)
) WITHOUT ROWID;

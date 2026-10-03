-- Immutable admitted action bindings survive pipeline/project deletion and
-- controller replacement. Source revisions are distinct from copied S3 versions.
ALTER TABLE codebuild_builds ADD COLUMN pipeline_action_id TEXT NOT NULL DEFAULT '';
CREATE TABLE codebuild_pipeline_inputs (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 artifact_name TEXT NOT NULL,
 location TEXT NOT NULL,
 version_id TEXT NOT NULL,
 revision_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id)
  REFERENCES codebuild_builds (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE codebuild_pipeline_outputs (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 artifact_name TEXT NOT NULL,
 location TEXT NOT NULL,
 encryption_key TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id)
  REFERENCES codebuild_builds (partition, account_id, region, resource_id) ON DELETE CASCADE
);

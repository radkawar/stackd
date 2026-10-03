CREATE TABLE ec2_instance_profile_associations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 instance_id TEXT NOT NULL,
 profile_arn TEXT NOT NULL,
 profile_id TEXT NOT NULL,
 state TEXT NOT NULL,
 timestamp DATETIME NOT NULL,
 next_action_at DATETIME,
 credential_id TEXT NOT NULL DEFAULT '',
 PRIMARY KEY (partition, account_id, region, resource_id),
 FOREIGN KEY (partition, account_id, region, instance_id) REFERENCES ec2_instances (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX ec2_instance_profile_current ON ec2_instance_profile_associations (partition, account_id, region, instance_id) WHERE state IN ('associating', 'associated');
CREATE INDEX ec2_instance_profile_deadline ON ec2_instance_profile_associations (next_action_at, partition, account_id, region, resource_id) WHERE next_action_at IS NOT NULL;

-- Upgrade the previous launch-only projection into the relationship owner.
UPDATE ec2_instances SET iam_instance_profile = CAST('null' AS BLOB) WHERE json_extract(CAST(state AS TEXT), '$.Name') = 'terminated';
INSERT INTO ec2_instance_profile_associations (partition, account_id, region, resource_id, instance_id, profile_arn, profile_id, state, timestamp)
SELECT partition, account_id, region, 'iip-assoc-' || substr(resource_id, 3), resource_id,
 json_extract(CAST(iam_instance_profile AS TEXT), '$.Arn'), json_extract(CAST(iam_instance_profile AS TEXT), '$.Id'), 'associated', launch_time
FROM ec2_instances WHERE json_extract(CAST(iam_instance_profile AS TEXT), '$.Arn') IS NOT NULL;

CREATE TABLE ec2_instance_metadata_devices (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 device_name TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_instances (partition, account_id, region, resource_id) ON DELETE CASCADE
);
-- Only devices whose retained attach time predates the last start are known to
-- have been present at that boot. Older databases cannot reconstruct devices
-- detached afterward; the next stop/start establishes the complete projection.
INSERT INTO ec2_instance_metadata_devices (partition, account_id, region, resource_id, position, device_name)
SELECT m.partition, m.account_id, m.region, m.resource_id, m.position, m.device_name
FROM ec2_instance_mappings m JOIN ec2_instances i USING (partition, account_id, region, resource_id)
WHERE m.ebs_present = 1 AND m.device_name IS NOT NULL AND m.attach_time <= i.launch_time;

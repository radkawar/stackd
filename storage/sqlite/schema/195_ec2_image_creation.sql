-- Optional work belongs to the pending image, not to a second resource catalog.
CREATE TABLE ec2_image_creations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 instance_id TEXT NOT NULL,
 instance_generation BLOB NOT NULL CHECK(length(instance_generation) = 8),
 no_reboot BOOLEAN NOT NULL,
 phase TEXT NOT NULL,
 next_action_at DATETIME,
 shutdown_deadline DATETIME,
 request_id TEXT NOT NULL,
 parent_event_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_images (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE INDEX ec2_image_creations_deadline ON ec2_image_creations (next_action_at, partition, account_id, region, resource_id) WHERE next_action_at IS NOT NULL;

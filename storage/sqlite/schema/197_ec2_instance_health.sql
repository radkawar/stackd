-- Replace unpopulated transport-shaped status blobs with native check state.
ALTER TABLE ec2_instances DROP COLUMN system_status;
ALTER TABLE ec2_instances DROP COLUMN guest_status;
ALTER TABLE ec2_instances ADD COLUMN health_updated_at DATETIME;
ALTER TABLE ec2_instances ADD COLUMN system_check_status TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_instances ADD COLUMN system_impaired_since DATETIME;
ALTER TABLE ec2_instances ADD COLUMN guest_check_status TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_instances ADD COLUMN guest_impaired_since DATETIME;
ALTER TABLE ec2_instances ADD COLUMN ebs_check_status TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_instances ADD COLUMN ebs_impaired_since DATETIME;

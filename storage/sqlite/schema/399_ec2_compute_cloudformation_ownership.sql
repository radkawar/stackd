ALTER TABLE ec2_instances ADD COLUMN cloudformation_resource_type TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_instances ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_launch_template ADD COLUMN cloudformation_resource_type TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_launch_template ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_key_pairs ADD COLUMN cloudformation_resource_type TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_key_pairs ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';

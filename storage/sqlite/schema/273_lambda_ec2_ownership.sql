ALTER TABLE ec2_network_interfaces ADD COLUMN lambda_mapping_owner_arn TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX ec2_lambda_source_mapping_owner ON ec2_network_interfaces(partition, account_id, region, lambda_mapping_owner_arn) WHERE lambda_mapping_owner_arn != '';
ALTER TABLE ec2_instances ADD COLUMN lambda_capacity_provider_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_instances ADD COLUMN lambda_managed_generation TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX ec2_lambda_managed_generation ON ec2_instances(partition, account_id, region, lambda_managed_generation) WHERE lambda_managed_generation != '';

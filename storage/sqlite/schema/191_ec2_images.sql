CREATE TABLE ec2_images (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 image_id TEXT,
 architecture TEXT,
 boot_mode TEXT,
 creation_date TEXT,
 deprecation_time TEXT,
 deregistration_protection TEXT,
 description TEXT,
 ena_support BOOLEAN,
 free_tier_eligible BOOLEAN,
 hypervisor TEXT,
 image_allowed BOOLEAN,
 image_location TEXT,
 image_owner_alias TEXT,
 image_type TEXT,
 imds_support TEXT,
 instance_type_specification BLOB NOT NULL,
 kernel_id TEXT,
 last_launched_time TEXT,
 name TEXT,
 owner_id TEXT,
 platform TEXT,
 platform_details TEXT,
 public BOOLEAN,
 public_ssm_parameter_name TEXT,
 ramdisk_id TEXT,
 root_device_name TEXT,
 root_device_type TEXT,
 source_image_id TEXT,
 source_image_region TEXT,
 source_instance_id TEXT,
 sriov_net_support TEXT,
 state TEXT,
 state_reason BLOB NOT NULL,
 tpm_support TEXT,
 usage_operation TEXT,
 virtualization_type TEXT,
 mappings_present BOOLEAN NOT NULL,
 tags_present BOOLEAN NOT NULL,
 permissions_present BOOLEAN NOT NULL,
 snapshot_owners_present BOOLEAN NOT NULL,
 products_present BOOLEAN NOT NULL,
 watermarks_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);
CREATE UNIQUE INDEX ec2_images_registered_name ON ec2_images (partition, account_id, region, name) WHERE state IS NULL OR state != 'deregistered';
CREATE INDEX ec2_images_region ON ec2_images (partition, region, resource_id);

CREATE TABLE ec2_image_mappings (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 device_name TEXT,
 no_device TEXT,
 virtual_name TEXT,
 ebs_present BOOLEAN NOT NULL,
 availability_zone TEXT,
 availability_zone_id TEXT,
 delete_on_termination BOOLEAN,
 ebs_card_index INTEGER,
 encrypted BOOLEAN,
 iops INTEGER,
 kms_key_id TEXT,
 outpost_arn TEXT,
 snapshot_id TEXT,
 snapshot_owner TEXT,
 throughput INTEGER,
 volume_initialization_rate INTEGER,
 volume_size INTEGER,
 volume_type TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_images (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE INDEX ec2_image_snapshot_references ON ec2_image_mappings (partition, region, snapshot_owner, snapshot_id);

CREATE TABLE ec2_image_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_images (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_image_permissions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 user_id TEXT,
 permission_group TEXT,
 organization_arn TEXT,
 organizational_unit_arn TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_images (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_image_products (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 product_code_id TEXT,
 product_code_type TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_images (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_image_watermarks (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 source_image_creation_time DATETIME,
 source_image_id TEXT,
 source_image_region TEXT,
 watermark_creation_time DATETIME,
 watermark_key TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_images (partition, account_id, region, resource_id) ON DELETE CASCADE
);

-- name: GetImage :one
SELECT * FROM ec2_images WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: GetRegionalImage :one
SELECT * FROM ec2_images WHERE partition = sqlc.arg(partition) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListImages :many
SELECT * FROM ec2_images WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: ListRegionalImages :many
SELECT * FROM ec2_images WHERE partition = sqlc.arg(partition) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: ImageReferencingSnapshot :one
SELECT i.resource_id FROM ec2_image_mappings m JOIN ec2_images i USING (partition, account_id, region, resource_id) WHERE m.partition = sqlc.arg(partition) AND m.region = sqlc.arg(region) AND m.snapshot_owner = sqlc.arg(snapshot_owner) AND m.snapshot_id = sqlc.arg(snapshot_id) AND (i.state IS NULL OR i.state != 'deregistered') ORDER BY i.resource_id LIMIT 1;

-- name: PutImage :exec
INSERT INTO ec2_images (partition, account_id, region, resource_id, image_id, architecture, boot_mode, creation_date, deprecation_time, deregistration_protection, description, ena_support, free_tier_eligible, hypervisor, image_allowed, image_location, image_owner_alias, image_type, imds_support, instance_type_specification, kernel_id, last_launched_time, name, owner_id, platform, platform_details, public, public_ssm_parameter_name, ramdisk_id, root_device_name, root_device_type, source_image_id, source_image_region, source_instance_id, sriov_net_support, state, state_reason, tpm_support, usage_operation, virtualization_type, mappings_present, tags_present, permissions_present, snapshot_owners_present, products_present, watermarks_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(image_id), sqlc.arg(architecture), sqlc.arg(boot_mode), sqlc.arg(creation_date), sqlc.arg(deprecation_time), sqlc.arg(deregistration_protection), sqlc.arg(description), sqlc.arg(ena_support), sqlc.arg(free_tier_eligible), sqlc.arg(hypervisor), sqlc.arg(image_allowed), sqlc.arg(image_location), sqlc.arg(image_owner_alias), sqlc.arg(image_type), sqlc.arg(imds_support), sqlc.arg(instance_type_specification), sqlc.arg(kernel_id), sqlc.arg(last_launched_time), sqlc.arg(name), sqlc.arg(owner_id), sqlc.arg(platform), sqlc.arg(platform_details), sqlc.arg(public), sqlc.arg(public_ssm_parameter_name), sqlc.arg(ramdisk_id), sqlc.arg(root_device_name), sqlc.arg(root_device_type), sqlc.arg(source_image_id), sqlc.arg(source_image_region), sqlc.arg(source_instance_id), sqlc.arg(sriov_net_support), sqlc.arg(state), sqlc.arg(state_reason), sqlc.arg(tpm_support), sqlc.arg(usage_operation), sqlc.arg(virtualization_type), sqlc.arg(mappings_present), sqlc.arg(tags_present), sqlc.arg(permissions_present), sqlc.arg(snapshot_owners_present), sqlc.arg(products_present), sqlc.arg(watermarks_present))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET image_id = excluded.image_id, architecture = excluded.architecture, boot_mode = excluded.boot_mode, creation_date = excluded.creation_date, deprecation_time = excluded.deprecation_time, deregistration_protection = excluded.deregistration_protection, description = excluded.description, ena_support = excluded.ena_support, free_tier_eligible = excluded.free_tier_eligible, hypervisor = excluded.hypervisor, image_allowed = excluded.image_allowed, image_location = excluded.image_location, image_owner_alias = excluded.image_owner_alias, image_type = excluded.image_type, imds_support = excluded.imds_support, instance_type_specification = excluded.instance_type_specification, kernel_id = excluded.kernel_id, last_launched_time = excluded.last_launched_time, name = excluded.name, owner_id = excluded.owner_id, platform = excluded.platform, platform_details = excluded.platform_details, public = excluded.public, public_ssm_parameter_name = excluded.public_ssm_parameter_name, ramdisk_id = excluded.ramdisk_id, root_device_name = excluded.root_device_name, root_device_type = excluded.root_device_type, source_image_id = excluded.source_image_id, source_image_region = excluded.source_image_region, source_instance_id = excluded.source_instance_id, sriov_net_support = excluded.sriov_net_support, state = excluded.state, state_reason = excluded.state_reason, tpm_support = excluded.tpm_support, usage_operation = excluded.usage_operation, virtualization_type = excluded.virtualization_type, mappings_present = excluded.mappings_present, tags_present = excluded.tags_present, permissions_present = excluded.permissions_present, snapshot_owners_present = excluded.snapshot_owners_present, products_present = excluded.products_present, watermarks_present = excluded.watermarks_present;

-- name: DeleteImage :execrows
DELETE FROM ec2_images WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListImageMappings :many
SELECT * FROM ec2_image_mappings WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutImageMapping :exec
INSERT INTO ec2_image_mappings (partition, account_id, region, resource_id, position, device_name, no_device, virtual_name, ebs_present, availability_zone, availability_zone_id, delete_on_termination, ebs_card_index, encrypted, iops, kms_key_id, outpost_arn, snapshot_id, snapshot_owner, throughput, volume_initialization_rate, volume_size, volume_type)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(device_name), sqlc.arg(no_device), sqlc.arg(virtual_name), sqlc.arg(ebs_present), sqlc.arg(availability_zone), sqlc.arg(availability_zone_id), sqlc.arg(delete_on_termination), sqlc.arg(ebs_card_index), sqlc.arg(encrypted), sqlc.arg(iops), sqlc.arg(kms_key_id), sqlc.arg(outpost_arn), sqlc.arg(snapshot_id), sqlc.arg(snapshot_owner), sqlc.arg(throughput), sqlc.arg(volume_initialization_rate), sqlc.arg(volume_size), sqlc.arg(volume_type));

-- name: DeleteImageMappings :exec
DELETE FROM ec2_image_mappings WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListImageTags :many
SELECT * FROM ec2_image_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutImageTag :exec
INSERT INTO ec2_image_tags (partition, account_id, region, resource_id, position, key, value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value));

-- name: DeleteImageTags :exec
DELETE FROM ec2_image_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListImagePermissions :many
SELECT * FROM ec2_image_permissions WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutImagePermission :exec
INSERT INTO ec2_image_permissions (partition, account_id, region, resource_id, position, user_id, permission_group, organization_arn, organizational_unit_arn) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(user_id), sqlc.arg(permission_group), sqlc.arg(organization_arn), sqlc.arg(organizational_unit_arn));

-- name: DeleteImagePermissions :exec
DELETE FROM ec2_image_permissions WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListImageProducts :many
SELECT * FROM ec2_image_products WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutImageProduct :exec
INSERT INTO ec2_image_products (partition, account_id, region, resource_id, position, product_code_id, product_code_type) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(product_code_id), sqlc.arg(product_code_type));

-- name: DeleteImageProducts :exec
DELETE FROM ec2_image_products WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListImageWatermarks :many
SELECT * FROM ec2_image_watermarks WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutImageWatermark :exec
INSERT INTO ec2_image_watermarks (partition, account_id, region, resource_id, position, source_image_creation_time, source_image_id, source_image_region, watermark_creation_time, watermark_key) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(source_image_creation_time), sqlc.arg(source_image_id), sqlc.arg(source_image_region), sqlc.arg(watermark_creation_time), sqlc.arg(watermark_key));

-- name: DeleteImageWatermarks :exec
DELETE FROM ec2_image_watermarks WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

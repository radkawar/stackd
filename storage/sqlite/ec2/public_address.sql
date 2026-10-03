-- name: GetPublicAddress :one
SELECT * FROM ec2_public_addresses WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListPublicAddresses :many
SELECT * FROM ec2_public_addresses WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: ListPublicIPv4Reservations :many
SELECT public_ip FROM ec2_public_addresses WHERE public_ip IS NOT NULL;

-- name: PutPublicAddress :exec
INSERT INTO ec2_public_addresses (partition, account_id, region, resource_id, automatic, public_ip, association_id, network_interface_id, private_ip_address, network_border_group, tags_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(automatic), sqlc.arg(public_ip), sqlc.arg(association_id), sqlc.arg(network_interface_id), sqlc.arg(private_ip_address), sqlc.arg(network_border_group), sqlc.arg(tags_present))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET automatic = excluded.automatic, public_ip = excluded.public_ip, association_id = excluded.association_id, network_interface_id = excluded.network_interface_id, private_ip_address = excluded.private_ip_address, network_border_group = excluded.network_border_group, tags_present = excluded.tags_present;

-- name: DeletePublicAddress :execrows
DELETE FROM ec2_public_addresses WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListPublicAddressTags :many
SELECT * FROM ec2_public_address_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutPublicAddressTag :exec
INSERT INTO ec2_public_address_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value));

-- name: DeletePublicAddressTags :exec
DELETE FROM ec2_public_address_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

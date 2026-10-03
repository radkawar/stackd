-- name: GetApplication :one
SELECT * FROM appregistry_applications
WHERE partition = ? AND account_id = ? AND region = ?
  AND (arn = sqlc.arg(identifier) OR id = sqlc.arg(identifier) OR name = sqlc.arg(identifier))
-- SQLC does not rewrite macros inside ORDER BY CASE; ?4 is the identifier above.
ORDER BY CASE WHEN arn = ?4 THEN 0 WHEN id = ?4 THEN 1 ELSE 2 END LIMIT 1;

-- name: ListApplications :many
SELECT * FROM appregistry_applications
WHERE partition = ? AND account_id = ? AND region = ? ORDER BY arn;

-- name: ListAccountApplications :many
SELECT * FROM appregistry_applications WHERE partition = ? AND account_id = ? ORDER BY arn;

-- name: PutApplication :execrows
INSERT INTO appregistry_applications (arn, partition, account_id, region, id, name, description, client_token, create_fingerprint, group_arn, tag_group_arn, created, modified)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(arn) DO UPDATE SET
    name = excluded.name, description = excluded.description, client_token = excluded.client_token,
    create_fingerprint = excluded.create_fingerprint,
    group_arn = excluded.group_arn, tag_group_arn = excluded.tag_group_arn,
    created = excluded.created, modified = excluded.modified
WHERE appregistry_applications.partition = excluded.partition
  AND appregistry_applications.account_id = excluded.account_id
  AND appregistry_applications.region = excluded.region
  AND appregistry_applications.id = excluded.id;

-- name: DeleteApplication :exec
DELETE FROM appregistry_applications WHERE arn = ?;

-- name: ListApplicationTags :many
SELECT * FROM appregistry_application_tags WHERE application_arn = ? ORDER BY tag_key;

-- name: PutApplicationTag :exec
INSERT INTO appregistry_application_tags (application_arn, tag_key, tag_value) VALUES (?, ?, ?);

-- name: DeleteApplicationTags :exec
DELETE FROM appregistry_application_tags WHERE application_arn = ?;

-- name: GetAttributeGroup :one
SELECT * FROM appregistry_attribute_groups
WHERE partition = ? AND account_id = ? AND region = ?
  AND (arn = sqlc.arg(identifier) OR id = sqlc.arg(identifier) OR name = sqlc.arg(identifier))
-- SQLC does not rewrite macros inside ORDER BY CASE; ?4 is the identifier above.
ORDER BY CASE WHEN arn = ?4 THEN 0 WHEN id = ?4 THEN 1 ELSE 2 END LIMIT 1;

-- name: ListAttributeGroups :many
SELECT * FROM appregistry_attribute_groups
WHERE partition = ? AND account_id = ? AND region = ? ORDER BY arn;

-- name: PutAttributeGroup :execrows
INSERT INTO appregistry_attribute_groups (arn, partition, account_id, region, id, name, description, attributes, client_token, create_fingerprint, created, modified)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(arn) DO UPDATE SET
    name = excluded.name, description = excluded.description, attributes = excluded.attributes,
    create_fingerprint = excluded.create_fingerprint,
    client_token = excluded.client_token, created = excluded.created, modified = excluded.modified
WHERE appregistry_attribute_groups.partition = excluded.partition
  AND appregistry_attribute_groups.account_id = excluded.account_id
  AND appregistry_attribute_groups.region = excluded.region
  AND appregistry_attribute_groups.id = excluded.id;

-- name: DeleteAttributeGroup :exec
DELETE FROM appregistry_attribute_groups WHERE arn = ?;

-- name: ListAttributeGroupTags :many
SELECT * FROM appregistry_attribute_group_tags WHERE attribute_group_arn = ? ORDER BY tag_key;

-- name: PutAttributeGroupTag :exec
INSERT INTO appregistry_attribute_group_tags (attribute_group_arn, tag_key, tag_value) VALUES (?, ?, ?);

-- name: DeleteAttributeGroupTags :exec
DELETE FROM appregistry_attribute_group_tags WHERE attribute_group_arn = ?;

-- name: ListAttributeLinks :many
SELECT attribute_group_arn FROM appregistry_attribute_links WHERE application_arn = ? ORDER BY attribute_group_arn;

-- name: PutAttributeLink :execrows
INSERT INTO appregistry_attribute_links (application_arn, attribute_group_arn)
SELECT a.arn, g.arn FROM appregistry_applications a JOIN appregistry_attribute_groups g
ON a.partition = g.partition AND a.account_id = g.account_id AND a.region = g.region
WHERE a.arn = sqlc.arg(application_arn) AND g.arn = sqlc.arg(attribute_group_arn)
ON CONFLICT(application_arn, attribute_group_arn) DO UPDATE SET attribute_group_arn = excluded.attribute_group_arn;

-- name: DeleteAttributeLink :exec
DELETE FROM appregistry_attribute_links WHERE application_arn = ? AND attribute_group_arn = ?;

-- name: ListAssociations :many
SELECT * FROM appregistry_resource_associations WHERE application_arn = ? ORDER BY resource_arn;

-- name: PutAssociation :exec
INSERT INTO appregistry_resource_associations (application_arn, resource_arn, resource_name, resource_type, incarnation, apply_tag, created)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(application_arn, resource_arn) DO UPDATE SET
    resource_name = excluded.resource_name, resource_type = excluded.resource_type,
    incarnation = excluded.incarnation, apply_tag = excluded.apply_tag, created = excluded.created;

-- name: DeleteAssociation :exec
DELETE FROM appregistry_resource_associations WHERE application_arn = ? AND resource_arn = ?;

-- name: GetConfiguration :one
SELECT * FROM appregistry_configurations WHERE partition = ? AND account_id = ? AND region = ?;

-- name: PutConfiguration :exec
INSERT INTO appregistry_configurations (partition, account_id, region, tag_key) VALUES (?, ?, ?, ?)
ON CONFLICT(partition, account_id, region) DO UPDATE SET tag_key = excluded.tag_key;

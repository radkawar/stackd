-- name: GetAccessPoint :one
SELECT * FROM s3_access_points WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetAccessPointAlias :one
SELECT * FROM s3_access_points WHERE partition = ? AND alias = ?;

-- name: ListAccessPoints :many
SELECT * FROM s3_access_points
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
AND name > sqlc.arg(after_name) COLLATE BINARY
AND (CAST(sqlc.arg(bucket_name) AS TEXT) = '' OR bucket_name = sqlc.arg(bucket_name))
ORDER BY name COLLATE BINARY LIMIT sqlc.arg(row_limit);

-- name: CountAccessPoints :one
SELECT count(*) FROM s3_access_points WHERE partition = ? AND account_id = ? AND region = ?;

-- name: PutAccessPoint :exec
INSERT INTO s3_access_points (
    partition, account_id, region, name, alias, bucket_partition, bucket_name, bucket_account_id, created, vpc_id,
    block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets, policy_document, policy_trust
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, name) DO UPDATE SET
alias = excluded.alias, bucket_partition = excluded.bucket_partition, bucket_name = excluded.bucket_name,
bucket_account_id = excluded.bucket_account_id, created = excluded.created, vpc_id = excluded.vpc_id,
block_public_acls = excluded.block_public_acls, ignore_public_acls = excluded.ignore_public_acls,
block_public_policy = excluded.block_public_policy, restrict_public_buckets = excluded.restrict_public_buckets,
policy_document = excluded.policy_document, policy_trust = excluded.policy_trust;

-- name: DeleteAccessPoint :execrows
DELETE FROM s3_access_points WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetAccessPointPolicyPrincipals :many
SELECT principal, principal_id FROM s3_access_point_policy_principals
WHERE partition = ? AND account_id = ? AND region = ? AND access_point_name = ?;

-- name: DeleteAccessPointPolicyPrincipals :exec
DELETE FROM s3_access_point_policy_principals WHERE partition = ? AND account_id = ? AND region = ? AND access_point_name = ?;

-- name: PutAccessPointPolicyPrincipal :exec
INSERT INTO s3_access_point_policy_principals (partition, account_id, region, access_point_name, principal, principal_id)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetAccessPointTags :many
SELECT key, value FROM s3_access_point_tags
WHERE partition = ? AND account_id = ? AND region = ? AND access_point_name = ? ORDER BY key COLLATE BINARY;

-- name: DeleteAccessPointTags :exec
DELETE FROM s3_access_point_tags WHERE partition = ? AND account_id = ? AND region = ? AND access_point_name = ?;

-- name: PutAccessPointTag :exec
INSERT INTO s3_access_point_tags (partition, account_id, region, access_point_name, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetBucket :one
SELECT * FROM s3_buckets WHERE partition = ? AND name = ?;

-- name: ListBuckets :many
SELECT * FROM s3_buckets WHERE partition = ? AND account_id = ? ORDER BY name COLLATE BINARY;

-- name: PutBucket :exec
INSERT INTO s3_buckets (partition, name, account_id, region, created, policy_document, policy_trust, ownership, versioning, encryption_algorithm, kms_key_id, owner_account_id, owner_id, acl_legacy, bucket_key_enabled, requester_pays,
object_lock_enabled, default_retention_mode, default_retention_days, default_retention_years, default_event_hold_days, default_event_hold_years, sse_customer_blocked, abac_enabled, acceleration_status, incarnation)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, name) DO UPDATE SET account_id = excluded.account_id, region = excluded.region,
created = excluded.created, policy_document = excluded.policy_document, policy_trust = excluded.policy_trust, ownership = excluded.ownership, versioning = excluded.versioning,
encryption_algorithm = excluded.encryption_algorithm, kms_key_id = excluded.kms_key_id, sse_customer_blocked = excluded.sse_customer_blocked, abac_enabled = excluded.abac_enabled, acceleration_status = excluded.acceleration_status,
owner_account_id = excluded.owner_account_id, owner_id = excluded.owner_id, acl_legacy = false, bucket_key_enabled = excluded.bucket_key_enabled, requester_pays = excluded.requester_pays,
object_lock_enabled = excluded.object_lock_enabled, default_retention_mode = excluded.default_retention_mode,
default_retention_days = excluded.default_retention_days, default_retention_years = excluded.default_retention_years,
default_event_hold_days = excluded.default_event_hold_days, default_event_hold_years = excluded.default_event_hold_years;

-- name: DeleteBucket :exec
DELETE FROM s3_buckets WHERE partition = ? AND name = ?;

-- name: GetBucketPolicyPrincipals :many
SELECT principal, principal_id FROM s3_bucket_policy_principals WHERE partition = ? AND bucket_name = ?;

-- name: DeleteBucketPolicyPrincipals :exec
DELETE FROM s3_bucket_policy_principals WHERE partition = ? AND bucket_name = ?;

-- name: PutBucketPolicyPrincipal :exec
INSERT INTO s3_bucket_policy_principals (partition, bucket_name, principal, principal_id) VALUES (?, ?, ?, ?);

-- name: GetBucketPublicAccess :one
SELECT * FROM s3_bucket_public_access WHERE partition = ? AND bucket_name = ?;

-- name: DeleteBucketPublicAccess :exec
DELETE FROM s3_bucket_public_access WHERE partition = ? AND bucket_name = ?;

-- name: PutBucketPublicAccess :exec
INSERT INTO s3_bucket_public_access (partition, bucket_name, block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, bucket_name) DO UPDATE SET block_public_acls = excluded.block_public_acls,
ignore_public_acls = excluded.ignore_public_acls, block_public_policy = excluded.block_public_policy, restrict_public_buckets = excluded.restrict_public_buckets;

-- name: GetAccountPublicAccessBlock :one
SELECT * FROM s3_account_public_access WHERE partition = ? AND account_id = ?;

-- name: DeleteAccountPublicAccessBlock :exec
DELETE FROM s3_account_public_access WHERE partition = ? AND account_id = ?;

-- name: PutAccountPublicAccessBlock :exec
INSERT INTO s3_account_public_access (partition, account_id, block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id) DO UPDATE SET block_public_acls = excluded.block_public_acls,
ignore_public_acls = excluded.ignore_public_acls, block_public_policy = excluded.block_public_policy, restrict_public_buckets = excluded.restrict_public_buckets;

-- name: GetBucketTags :many
SELECT key, value FROM s3_bucket_tags WHERE partition = ? AND bucket_name = ? ORDER BY key COLLATE BINARY;

-- name: DeleteBucketTags :exec
DELETE FROM s3_bucket_tags WHERE partition = ? AND bucket_name = ?;

-- name: PutBucketTag :exec
INSERT INTO s3_bucket_tags (partition, bucket_name, key, value) VALUES (?, ?, ?, ?);

-- name: GetObject :one
SELECT * FROM s3_object_versions WHERE partition = ? AND bucket_name = ? AND name = ?
ORDER BY created_order DESC LIMIT 1;

-- name: GetObjectVersion :one
SELECT * FROM s3_object_versions WHERE partition = ? AND bucket_name = ? AND name = ? AND version_id = ?;

-- name: ListObjects :many
SELECT v.* FROM s3_object_versions AS v
WHERE v.partition = sqlc.arg(partition) AND v.bucket_name = sqlc.arg(bucket_name)
AND v.name > sqlc.arg(after_key) COLLATE BINARY
AND substr(CAST(v.name AS BLOB), 1, length(CAST(sqlc.arg(prefix) AS BLOB))) = CAST(sqlc.arg(prefix) AS BLOB)
AND NOT v.delete_marker
AND NOT EXISTS (
    SELECT 1 FROM s3_object_versions AS newer
    WHERE newer.partition = v.partition AND newer.bucket_name = v.bucket_name AND newer.name = v.name AND newer.created_order > v.created_order
)
ORDER BY v.name COLLATE BINARY LIMIT sqlc.arg(row_limit);

-- name: ListObjectVersions :many
SELECT v.* FROM s3_object_versions AS v
WHERE v.partition = sqlc.arg(partition) AND v.bucket_name = sqlc.arg(bucket_name)
AND substr(CAST(v.name AS BLOB), 1, length(CAST(sqlc.arg(prefix) AS BLOB))) = CAST(sqlc.arg(prefix) AS BLOB)
AND (v.name > sqlc.arg(after_key) COLLATE BINARY OR (
    v.name = sqlc.arg(after_key) COLLATE BINARY
    AND v.created_order < COALESCE(sqlc.narg(after_order), (
        SELECT cursor.created_order FROM s3_object_versions AS cursor
        WHERE cursor.partition = sqlc.arg(partition) AND cursor.bucket_name = sqlc.arg(bucket_name)
        AND cursor.name = sqlc.arg(after_key) AND cursor.version_id = sqlc.arg(after_version)
    ))
))
ORDER BY v.name COLLATE BINARY, v.created_order DESC LIMIT sqlc.arg(row_limit);

-- name: NextObjectSequence :one
UPDATE s3_object_version_sequence SET sequence = sequence + 1 WHERE singleton = 1 RETURNING sequence;

-- name: PutObjectVersion :exec
INSERT INTO s3_object_versions (partition, bucket_name, name, version_id, sequence, delete_marker, modified, size, etag, checksum_algorithm, checksum,
content_type, content_encoding, content_language, content_disposition, cache_control, expires, encryption_algorithm, kms_key_arn, website_redirect_location,
created_order, upload_id, checksum_type, owner_account_id, owner_id, acl_legacy,
retention_mode, retain_until, event_hold, event_hold_days, event_hold_years, legal_hold, retention_modified, legal_hold_modified, storage_class, replica,
tiering_accessed, archive_tier, multipart_checksum_explicit)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ReplaceObjectVersionRetention :execrows
UPDATE s3_object_versions SET retention_mode = ?, retain_until = ?, event_hold = ?, event_hold_days = ?, event_hold_years = ?, retention_modified = ?
WHERE partition = ? AND bucket_name = ? AND name = ? AND version_id = ?;

-- name: ReplaceObjectVersionLegalHold :execrows
UPDATE s3_object_versions SET legal_hold = ?, legal_hold_modified = ?
WHERE partition = ? AND bucket_name = ? AND name = ? AND version_id = ?;

-- name: DeleteObjectVersion :exec
DELETE FROM s3_object_versions WHERE partition = ? AND bucket_name = ? AND name = ? AND version_id = ?;

-- name: GetObjectVersionMetadata :many
SELECT key, value FROM s3_object_version_metadata WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?;

-- name: PutObjectVersionMetadata :exec
INSERT INTO s3_object_version_metadata (partition, bucket_name, object_name, version_id, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetObjectVersionEncryptionContext :many
SELECT key, value FROM s3_object_version_encryption_context WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?;

-- name: PutObjectVersionEncryptionContext :exec
INSERT INTO s3_object_version_encryption_context (partition, bucket_name, object_name, version_id, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetObjectVersionEncryptionMetadata :one
SELECT encryption_key, customer_key_salt, customer_key_hash, customer_key_md5
FROM s3_object_version_data WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?;

-- name: GetObjectVersionData :one
SELECT ciphertext FROM s3_object_version_data WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?;

-- name: PutObjectVersionData :exec
INSERT INTO s3_object_version_data (partition, bucket_name, object_name, version_id, encryption_key, ciphertext,
customer_key_salt, customer_key_hash, customer_key_md5) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetNotificationState :one
SELECT * FROM s3_notification_states WHERE partition = ? AND bucket_name = ?;

-- name: NextNotificationChange :one
SELECT partition, bucket_name, apply_at, version FROM s3_notification_states
WHERE apply_at IS NOT NULL ORDER BY apply_at, (partition || ':' || bucket_name) COLLATE BINARY LIMIT 1;

-- name: PutNotificationState :exec
INSERT INTO s3_notification_states (partition, bucket_name, desired_event_bridge, applied_event_bridge, apply_at, version)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, bucket_name) DO UPDATE SET desired_event_bridge = excluded.desired_event_bridge,
applied_event_bridge = excluded.applied_event_bridge, apply_at = excluded.apply_at, version = excluded.version;

-- name: DeleteNotificationRules :exec
DELETE FROM s3_notification_rules WHERE partition = ? AND bucket_name = ?;

-- name: ListNotificationRules :many
SELECT * FROM s3_notification_rules WHERE partition = ? AND bucket_name = ? AND applied = ? ORDER BY position;

-- name: PutNotificationRule :exec
INSERT INTO s3_notification_rules (partition, bucket_name, applied, position, id, protocol, destination_arn)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListNotificationEvents :many
SELECT event FROM s3_notification_events WHERE partition = ? AND bucket_name = ? AND applied = ? AND rule_position = ? ORDER BY position;

-- name: PutNotificationEvent :exec
INSERT INTO s3_notification_events (partition, bucket_name, applied, rule_position, position, event)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListNotificationFilters :many
SELECT name, value FROM s3_notification_filters WHERE partition = ? AND bucket_name = ? AND applied = ? AND rule_position = ? ORDER BY position;

-- name: PutNotificationFilter :exec
INSERT INTO s3_notification_filters (partition, bucket_name, applied, rule_position, position, name, value)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetNotificationDelivery :one
SELECT * FROM s3_notification_deliveries WHERE id = ?;

-- name: NextNotificationDelivery :one
SELECT id, due, version FROM s3_notification_deliveries ORDER BY due, id COLLATE BINARY LIMIT 1;

-- name: PutNotificationDelivery :exec
INSERT INTO s3_notification_deliveries (id, partition, bucket_name, account_id, region, protocol, destination_arn, payload, request_id, parent_event_id, due, attempts, version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET due = excluded.due, attempts = excluded.attempts, version = excluded.version;

-- name: DeleteNotificationDelivery :exec
DELETE FROM s3_notification_deliveries WHERE id = ?;

-- name: GetObjectTags :many
SELECT key, value FROM s3_object_version_tags
WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?
ORDER BY key COLLATE BINARY;

-- name: DeleteObjectTags :exec
DELETE FROM s3_object_version_tags
WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?;

-- name: PutObjectTag :exec
INSERT INTO s3_object_version_tags (partition, bucket_name, object_name, version_id, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetMultipartUpload :one
SELECT * FROM s3_multipart_uploads WHERE partition = ? AND bucket_name = ? AND object_name = ? AND upload_id = ?;

-- name: ListMultipartUploads :many
SELECT u.* FROM s3_multipart_uploads AS u
WHERE u.partition = sqlc.arg(partition) AND u.bucket_name = sqlc.arg(bucket_name)
AND substr(CAST(u.object_name AS BLOB), 1, length(CAST(sqlc.arg(prefix) AS BLOB))) = CAST(sqlc.arg(prefix) AS BLOB)
AND (u.object_name > sqlc.arg(after_key) COLLATE BINARY OR (
    u.object_name = sqlc.arg(after_key) COLLATE BINARY AND u.created_order > sqlc.narg(after_order)
))
ORDER BY u.object_name COLLATE BINARY, u.created_order LIMIT sqlc.arg(row_limit);

-- name: PutMultipartUpload :exec
INSERT INTO s3_multipart_uploads (partition, bucket_name, object_name, upload_id, created_order, modified,
initiator, superseded, size, etag, checksum_algorithm, checksum, checksum_type,
content_type, content_encoding, content_language, content_disposition, cache_control, expires,
website_redirect_location, encryption_algorithm, kms_key_arn, owner_account_id, owner_id, acl_legacy,
retention_mode, retain_until, event_hold, event_hold_days, event_hold_years, legal_hold, retention_modified, legal_hold_modified, storage_class)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteMultipartUpload :exec
DELETE FROM s3_multipart_uploads WHERE partition = ? AND bucket_name = ? AND object_name = ? AND upload_id = ?;

-- name: SupersedeOlderMultipartUploads :exec
UPDATE s3_multipart_uploads SET superseded = true
WHERE partition = ? AND bucket_name = ? AND object_name = ? AND created_order < ?;

-- name: SupersedeDeletedMultipartUploads :exec
UPDATE s3_multipart_uploads SET superseded = true
WHERE s3_multipart_uploads.partition = sqlc.arg(partition) AND s3_multipart_uploads.bucket_name = sqlc.arg(bucket_name) AND s3_multipart_uploads.object_name = sqlc.arg(object_name)
AND (
    sqlc.arg(version_id) = (
        SELECT v.version_id FROM s3_object_versions AS v
        WHERE v.partition = sqlc.arg(partition) AND v.bucket_name = sqlc.arg(bucket_name) AND v.name = sqlc.arg(object_name)
        ORDER BY v.created_order DESC LIMIT 1
    )
    OR (
        CAST(sqlc.arg(version_id) AS TEXT) = 'null'
        AND NOT EXISTS (
            SELECT 1 FROM s3_object_versions AS v
            WHERE v.partition = sqlc.arg(partition) AND v.bucket_name = sqlc.arg(bucket_name)
            AND v.name = sqlc.arg(object_name) AND v.version_id = 'null'
        )
        AND EXISTS (
            SELECT 1 FROM s3_buckets AS b
            WHERE b.partition = sqlc.arg(partition) AND b.name = sqlc.arg(bucket_name) AND b.versioning = ''
        )
    )
);

-- name: GetCompletedMultipartUpload :one
SELECT * FROM s3_object_versions WHERE partition = ? AND bucket_name = ? AND name = ? AND upload_id = ? AND upload_id <> '';

-- name: GetMultipartUploadMetadata :many
SELECT key, value FROM s3_multipart_upload_metadata WHERE partition = ? AND bucket_name = ? AND object_name = ? AND upload_id = ?;

-- name: PutMultipartUploadMetadata :exec
INSERT INTO s3_multipart_upload_metadata (partition, bucket_name, object_name, upload_id, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetMultipartUploadTags :many
SELECT key, value FROM s3_multipart_upload_tags WHERE partition = ? AND bucket_name = ? AND object_name = ? AND upload_id = ? ORDER BY key COLLATE BINARY;

-- name: PutMultipartUploadTag :exec
INSERT INTO s3_multipart_upload_tags (partition, bucket_name, object_name, upload_id, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: PublishMultipartUploadTags :exec
INSERT INTO s3_object_version_tags (partition, bucket_name, object_name, version_id, key, value)
SELECT t.partition, t.bucket_name, t.object_name, CAST(sqlc.arg(version_id) AS TEXT), t.key, t.value FROM s3_multipart_upload_tags AS t
WHERE t.partition = sqlc.arg(partition) AND t.bucket_name = sqlc.arg(bucket_name) AND t.object_name = sqlc.arg(object_name) AND t.upload_id = sqlc.arg(upload_id);

-- name: GetMultipartUploadEncryptionContext :many
SELECT key, value FROM s3_multipart_upload_encryption_context WHERE partition = ? AND bucket_name = ? AND object_name = ? AND upload_id = ?;

-- name: PutMultipartUploadEncryptionContext :exec
INSERT INTO s3_multipart_upload_encryption_context (partition, bucket_name, object_name, upload_id, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetMultipartUploadEncryptionMetadata :one
SELECT encryption_key, customer_key_salt, customer_key_hash, customer_key_md5
FROM s3_multipart_upload_encryption_keys WHERE partition = ? AND bucket_name = ? AND object_name = ? AND upload_id = ?;

-- name: PutMultipartUploadEncryptionMetadata :exec
INSERT INTO s3_multipart_upload_encryption_keys (partition, bucket_name, object_name, upload_id, encryption_key,
customer_key_salt, customer_key_hash, customer_key_md5) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListMultipartParts :many
SELECT number, modified, size, etag, checksum FROM s3_encrypted_parts
WHERE partition = sqlc.arg(partition) AND bucket_name = sqlc.arg(bucket_name) AND object_name = sqlc.arg(object_name)
AND upload_id = sqlc.narg(upload_id) AND number > sqlc.arg(after_number)
ORDER BY number LIMIT sqlc.arg(row_limit);

-- name: ListObjectParts :many
SELECT number, modified, size, etag, checksum FROM s3_encrypted_parts
WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?
ORDER BY number;

-- name: GetMultipartObjectData :many
SELECT ciphertext FROM s3_encrypted_parts WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?
ORDER BY number;

-- name: PutMultipartPart :exec
INSERT INTO s3_encrypted_parts (partition, bucket_name, object_name, upload_id, number, modified, size, etag, checksum, ciphertext)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, bucket_name, object_name, upload_id, number)
DO UPDATE SET modified = excluded.modified, size = excluded.size, etag = excluded.etag, checksum = excluded.checksum, ciphertext = excluded.ciphertext;

-- name: PublishMultipartPart :execrows
UPDATE s3_encrypted_parts SET upload_id = NULL, version_id = sqlc.narg(version_id)
WHERE partition = sqlc.arg(partition) AND bucket_name = sqlc.arg(bucket_name) AND object_name = sqlc.arg(object_name) AND upload_id = sqlc.narg(upload_id) AND number = sqlc.arg(number);

-- name: GetBucketACLGrants :many
SELECT grantee_type, grantee_id, grantee_uri, permission FROM s3_bucket_acl_grants
WHERE partition = ? AND bucket_name = ? ORDER BY position;

-- name: DeleteBucketACLGrants :exec
DELETE FROM s3_bucket_acl_grants WHERE partition = ? AND bucket_name = ?;

-- name: PutBucketACLGrant :exec
INSERT INTO s3_bucket_acl_grants (partition, bucket_name, position, grantee_type, grantee_id, grantee_uri, permission)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetObjectVersionACLGrants :many
SELECT grantee_type, grantee_id, grantee_uri, permission FROM s3_object_version_acl_grants
WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ? ORDER BY position;

-- name: DeleteObjectVersionACLGrants :exec
DELETE FROM s3_object_version_acl_grants WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?;

-- name: PutObjectVersionACLGrant :exec
INSERT INTO s3_object_version_acl_grants (partition, bucket_name, object_name, version_id, position, grantee_type, grantee_id, grantee_uri, permission)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ReplaceObjectVersionACLOwner :execrows
UPDATE s3_object_versions SET owner_account_id = ?, owner_id = ?, acl_legacy = false
WHERE partition = ? AND bucket_name = ? AND name = ? AND version_id = ?;

-- name: GetMultipartUploadACLGrants :many
SELECT grantee_type, grantee_id, grantee_uri, permission FROM s3_multipart_upload_acl_grants
WHERE partition = ? AND bucket_name = ? AND object_name = ? AND upload_id = ? ORDER BY position;

-- name: PutMultipartUploadACLGrant :exec
INSERT INTO s3_multipart_upload_acl_grants (partition, bucket_name, object_name, upload_id, position, grantee_type, grantee_id, grantee_uri, permission)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

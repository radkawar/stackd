-- name: GetPublishingDestination :one
SELECT * FROM guardduty_publishing_destinations WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND id=?;
-- name: ListPublishingDestinations :many
SELECT * FROM guardduty_publishing_destinations WHERE partition=? AND account_id=? AND region=? AND detector_id=? ORDER BY id;
-- name: PutPublishingDestination :exec
INSERT INTO guardduty_publishing_destinations (cfn_owner,cfn_token,partition,account_id,region,detector_id,id,arn,type,client_token,destination_arn,kms_key_arn,status,version,created,updated,failure_started,tags_present)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,detector_id,id) DO UPDATE SET arn=excluded.arn,type=excluded.type,client_token=excluded.client_token,destination_arn=excluded.destination_arn,kms_key_arn=excluded.kms_key_arn,status=excluded.status,version=excluded.version,created=excluded.created,updated=excluded.updated,failure_started=excluded.failure_started,tags_present=excluded.tags_present;
-- name: DeletePublishingDestination :exec
DELETE FROM guardduty_publishing_destinations WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND id=?;
-- name: ListPublishingDestinationTags :many
SELECT tag_key,tag_value FROM guardduty_publishing_destination_tags WHERE arn=? ORDER BY tag_key;
-- name: DeletePublishingDestinationTags :exec
DELETE FROM guardduty_publishing_destination_tags WHERE arn=?;
-- name: PutPublishingDestinationTag :exec
INSERT INTO guardduty_publishing_destination_tags (arn,tag_key,tag_value) VALUES (?,?,?);
-- name: GetFindingExport :one
SELECT * FROM guardduty_finding_exports WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND destination_id=? AND finding_id=?;
-- name: ListFindingExports :many
SELECT * FROM guardduty_finding_exports WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND destination_id=? ORDER BY finding_id;
-- name: NextFindingExport :one
SELECT finding_id,id,version,due FROM guardduty_finding_exports
WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND destination_id=? AND due>?
ORDER BY due,finding_id LIMIT 1;
-- name: PutFindingExport :exec
INSERT INTO guardduty_finding_exports (partition,account_id,region,detector_id,destination_id,finding_id,id,object_key,parent_event_id,destination_version,version,created,due,last_published,payload)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,detector_id,destination_id,finding_id) DO UPDATE SET id=excluded.id,object_key=excluded.object_key,parent_event_id=excluded.parent_event_id,destination_version=excluded.destination_version,version=excluded.version,created=excluded.created,due=excluded.due,last_published=excluded.last_published,payload=excluded.payload;
-- name: DeleteFindingExport :exec
DELETE FROM guardduty_finding_exports WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND destination_id=? AND finding_id=?;
-- name: DeleteDestinationExports :exec
DELETE FROM guardduty_finding_exports WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND destination_id=?;

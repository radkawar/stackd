-- name: GetDocument :one
SELECT * FROM ssm_documents WHERE partition=? AND account_id=? AND region=? AND name=?;
-- name: ListDocuments :many
SELECT * FROM ssm_documents WHERE partition=? AND account_id=? AND region=? ORDER BY name;
-- name: ListSharedDocuments :many
SELECT d.* FROM ssm_documents AS d
WHERE d.partition=sqlc.arg(partition) AND d.region=sqlc.arg(region) AND d.account_id<>sqlc.arg(recipient_account_id)
AND EXISTS (SELECT 1 FROM ssm_document_shares AS s WHERE s.document_id=d.id AND s.account_id IN (sqlc.arg(recipient_account_id),'all'))
ORDER BY d.account_id,d.name;
-- name: ListShares :many
SELECT account_id,version_selector FROM ssm_document_shares WHERE document_id=? ORDER BY account_id;
-- name: ClearShares :exec
DELETE FROM ssm_document_shares WHERE document_id=?;
-- name: InsertShare :exec
INSERT INTO ssm_document_shares(document_id,account_id,version_selector) VALUES(?,?,?);
-- name: PutDocument :one
INSERT INTO ssm_documents(partition,account_id,region,name,document_uuid,default_version,latest_version,next_version,document_type,schema_name,schema_version,schema_document_uuid) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,name) DO UPDATE SET document_uuid=excluded.document_uuid,default_version=excluded.default_version,latest_version=excluded.latest_version,next_version=excluded.next_version,document_type=excluded.document_type,schema_name=excluded.schema_name,schema_version=excluded.schema_version,schema_document_uuid=excluded.schema_document_uuid RETURNING id;
-- name: DeleteDocument :exec
DELETE FROM ssm_documents WHERE partition=? AND account_id=? AND region=? AND name=?;
-- name: ListTags :many
SELECT * FROM ssm_document_tags WHERE document_id=? ORDER BY tag_key;
-- name: ClearTags :exec
DELETE FROM ssm_document_tags WHERE document_id=?;
-- name: InsertTag :exec
INSERT INTO ssm_document_tags(document_id,tag_key,value) VALUES(?,?,?);
-- name: GetVersion :one
SELECT * FROM ssm_document_versions WHERE document_id=? AND version=?;
-- name: ListVersions :many
SELECT * FROM ssm_document_versions WHERE document_id=? ORDER BY version;
-- name: InsertVersion :exec
INSERT INTO ssm_document_versions(document_id,version,content,format,hash,version_name,display_name,target_type,created,status,ready_at) VALUES(?,?,?,?,?,?,?,?,?,?,?);
-- name: DeleteVersion :exec
DELETE FROM ssm_document_versions WHERE document_id=? AND version=?;
-- name: ActivateVersion :exec
UPDATE ssm_document_versions SET status='Active' WHERE document_id=? AND version=?;
-- name: NextActivation :one
SELECT d.partition,d.account_id,d.region,d.name,d.document_uuid,v.version,v.ready_at
FROM ssm_document_versions AS v JOIN ssm_documents AS d ON d.id=v.document_id
WHERE v.status IN ('Creating','Updating')
ORDER BY v.ready_at,d.partition,d.account_id,d.region,d.name,v.version LIMIT 1;

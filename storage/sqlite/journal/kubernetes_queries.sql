-- name: FindKubernetesAudit :one
SELECT sequence FROM kubernetes_audit_events WHERE partition=? AND account_id=? AND region=? AND cluster_id=? AND audit_id=? AND stage=?;

-- name: AppendKubernetesAudit :exec
INSERT INTO kubernetes_audit_events (sequence,partition,account_id,region,cluster_arn,cluster_id,cluster_name,audit_id,stage,verb,request_uri,user_name,user_uid,actor_user_name,source_ip,namespace,resource,subresource,name,user_agent,api_version,response_code,native_at,role_ref_api_group,role_ref_kind,role_ref_name,delete_options_observed,dry_run) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);

-- name: AppendKubernetesAuditGroup :exec
INSERT INTO kubernetes_audit_groups (sequence,position,name) VALUES (?,?,?);

-- name: ReadKubernetesAudit :one
SELECT * FROM kubernetes_audit_events WHERE sequence=?;

-- name: ReadKubernetesAuditGroups :many
SELECT name FROM kubernetes_audit_groups WHERE sequence=? ORDER BY position;

-- name: AppendKubernetesAuditSubject :exec
INSERT INTO kubernetes_audit_subjects (sequence,position,api_group,kind,name,namespace) VALUES (?,?,?,?,?,?);

-- name: ReadKubernetesAuditSubjects :many
SELECT api_group,kind,name,namespace FROM kubernetes_audit_subjects WHERE sequence=? ORDER BY position;

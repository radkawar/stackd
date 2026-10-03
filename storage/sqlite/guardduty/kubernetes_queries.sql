-- name: PutKubernetesObservation :execrows
INSERT INTO guardduty_observation_kubernetes (partition,account_id,region,detector_id,id,sequence)
SELECT k.partition,k.account_id,k.region,sqlc.arg(detector_id),sqlc.arg(id),k.sequence FROM kubernetes_audit_events k
WHERE k.partition=sqlc.arg(partition) AND k.account_id=sqlc.arg(account_id) AND k.region=sqlc.arg(region) AND k.cluster_id=sqlc.arg(cluster_id) AND k.audit_id=sqlc.arg(audit_id) AND k.stage=sqlc.arg(stage)
ON CONFLICT(partition,account_id,region,detector_id,id) DO UPDATE SET sequence=excluded.sequence;

-- name: DeleteKubernetesObservation :exec
DELETE FROM guardduty_observation_kubernetes WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND id=?;

-- name: GetKubernetesObservation :one
SELECT k.* FROM guardduty_observation_kubernetes o JOIN kubernetes_audit_events k USING(sequence)
WHERE o.partition=? AND o.account_id=? AND o.region=? AND o.detector_id=? AND o.id=?;

-- name: ListKubernetesObservations :many
SELECT o.id AS finding_id,sqlc.embed(k) FROM guardduty_observation_kubernetes o JOIN kubernetes_audit_events k USING(sequence)
WHERE o.partition=? AND o.account_id=? AND o.region=? AND o.detector_id=? ORDER BY o.id;

-- name: GetKubernetesObservationGroups :many
SELECT name FROM kubernetes_audit_groups WHERE sequence=? ORDER BY position;

-- name: ListKubernetesObservationGroups :many
SELECT o.id,g.name FROM guardduty_observation_kubernetes o JOIN kubernetes_audit_groups g USING(sequence)
WHERE o.partition=? AND o.account_id=? AND o.region=? AND o.detector_id=? ORDER BY o.id,g.position;

-- name: GetKubernetesObservationSubjects :many
SELECT api_group,kind,name,namespace FROM kubernetes_audit_subjects WHERE sequence=? ORDER BY position;

-- name: ListKubernetesObservationSubjects :many
SELECT o.id,s.api_group,s.kind,s.name,s.namespace FROM guardduty_observation_kubernetes o JOIN kubernetes_audit_subjects s USING(sequence)
WHERE o.partition=? AND o.account_id=? AND o.region=? AND o.detector_id=? ORDER BY o.id,s.position;

-- name: GetOutcomeDelivery :one
SELECT * FROM lambda_outcome_deliveries WHERE id=?;

-- name: NextOutcomeDelivery :one
SELECT d.id, i.completed FROM lambda_outcome_deliveries AS d
JOIN lambda_invocations AS i ON i.id=d.invocation_id
WHERE i.state='completed' ORDER BY i.completed,d.id LIMIT 1;

-- name: PutOutcomeDelivery :exec
INSERT INTO lambda_outcome_deliveries(id,invocation_id,destination_arn,dead_letter)
VALUES(?,?,?,?) ON CONFLICT(id) DO NOTHING;

-- name: DeleteOutcomeDelivery :exec
DELETE FROM lambda_outcome_deliveries WHERE id=?;

-- name: CollectCompletedInvocation :exec
DELETE FROM lambda_invocations WHERE lambda_invocations.id=? AND lambda_invocations.state='completed'
AND NOT EXISTS (SELECT 1 FROM lambda_outcome_deliveries WHERE lambda_outcome_deliveries.invocation_id=lambda_invocations.id);

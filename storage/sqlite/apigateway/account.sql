-- name: GetAccount :one
SELECT cloudwatch_role_arn FROM apigateway_accounts
WHERE partition = ? AND account_id = ? AND region = ?;

-- name: PutAccount :exec
INSERT INTO apigateway_accounts (partition, account_id, region, cloudwatch_role_arn)
VALUES (?, ?, ?, ?)
ON CONFLICT (partition, account_id, region) DO UPDATE SET cloudwatch_role_arn = excluded.cloudwatch_role_arn;

-- name: GetAccount :one
SELECT * FROM apigateway_accounts
WHERE partition = ? AND account_id = ? AND region = ?;

-- name: PutAccount :exec
INSERT INTO apigateway_accounts (partition, account_id, region, cloudwatch_role_arn, cfn_stack_id, cfn_logical_id, cfn_incarnation)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region) DO UPDATE SET cloudwatch_role_arn = excluded.cloudwatch_role_arn, cfn_stack_id = excluded.cfn_stack_id, cfn_logical_id = excluded.cfn_logical_id, cfn_incarnation = excluded.cfn_incarnation;

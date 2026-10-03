CREATE INDEX stepfunctions_open_execution_counts
ON stepfunctions_executions(partition, account_id, region)
WHERE type = 'STANDARD' AND status = 'RUNNING';

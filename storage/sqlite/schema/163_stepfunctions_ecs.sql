ALTER TABLE stepfunctions_revisions ADD COLUMN needs_ecs_sync BOOLEAN NOT NULL DEFAULT FALSE;

-- Older nested submissions retained only their accepted execution identity.
-- Preserve that same non-secret identity in the shared accepted response before
-- removing the integration-specific column. Terminal output is unchanged.
UPDATE stepfunctions_tasks
SET output = json_object('ExecutionArn', child_execution_arn)
WHERE kind = 'sync' AND status IN ('SUBMITTED', 'SCHEDULED', 'RUNNING')
  AND child_execution_arn <> '' AND output = '' AND encrypted_content IS NULL;

ALTER TABLE stepfunctions_tasks DROP COLUMN child_execution_arn;

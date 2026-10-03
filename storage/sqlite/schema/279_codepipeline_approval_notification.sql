-- Publication completion belongs to the retained approval action, not its public execution ID.
ALTER TABLE codepipeline_action_executions ADD COLUMN approval_notification_id TEXT NOT NULL DEFAULT '';

ALTER TABLE codepipeline_executions ADD COLUMN rollback_target_id TEXT NOT NULL DEFAULT '';
ALTER TABLE codepipeline_executions ADD COLUMN rollback_stage_index INTEGER NOT NULL DEFAULT 0;

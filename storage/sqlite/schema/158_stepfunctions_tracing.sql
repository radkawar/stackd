ALTER TABLE stepfunctions_executions ADD COLUMN trace_segment_id TEXT NOT NULL DEFAULT '';
ALTER TABLE stepfunctions_history ADD COLUMN frame_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stepfunctions_history ADD COLUMN state_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stepfunctions_frames ADD COLUMN started_history_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stepfunctions_history ADD COLUMN redrive_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stepfunctions_history ADD COLUMN error TEXT NOT NULL DEFAULT '';
ALTER TABLE stepfunctions_history ADD COLUMN cause TEXT NOT NULL DEFAULT '';

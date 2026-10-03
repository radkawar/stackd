ALTER TABLE stepfunctions_executions ADD COLUMN redrive_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stepfunctions_executions ADD COLUMN redriven DATETIME;
ALTER TABLE stepfunctions_executions ADD COLUMN map_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stepfunctions_map_runs ADD COLUMN redrive_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stepfunctions_map_runs ADD COLUMN redriven DATETIME;
ALTER TABLE stepfunctions_frames ADD COLUMN child_generation INTEGER NOT NULL DEFAULT 0;
UPDATE stepfunctions_frames SET child_generation = retry_count;

CREATE TABLE stepfunctions_redrive_requests (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 execution_arn TEXT NOT NULL,
 token TEXT NOT NULL,
 count INTEGER NOT NULL,
 date DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, execution_arn, token),
 FOREIGN KEY (partition, account_id, region, execution_arn)
 REFERENCES stepfunctions_executions(partition, account_id, region, arn) ON DELETE CASCADE
);

CREATE TABLE stepfunctions_map_result_files (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 map_run_arn TEXT NOT NULL,
 generation INTEGER NOT NULL,
 status TEXT NOT NULL,
 file_index INTEGER NOT NULL,
 key TEXT NOT NULL,
 size INTEGER NOT NULL,
 first_execution TEXT NOT NULL,
 last_execution TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, map_run_arn, generation, status, file_index),
 FOREIGN KEY (partition, account_id, region, map_run_arn)
 REFERENCES stepfunctions_map_runs(partition, account_id, region, arn) ON DELETE CASCADE
);

-- Function configuration belongs to the exact deployment snapshot.
CREATE TABLE lambda_function_durable_configs (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL, version INTEGER NOT NULL,
 execution_timeout INTEGER, retention_days INTEGER, kms_key_arn TEXT,
 PRIMARY KEY(partition,account,region,function_name,pending,version),
 FOREIGN KEY(partition,account,region,function_name,pending,version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);

-- Executions retain their admitted function identity after function deletion.
-- Encrypted executions retain only AEAD-protected payload/error scalars; their
-- admitted KMS key and wrapped data key are immutable execution identity.
CREATE TABLE lambda_durable_executions (
 arn TEXT PRIMARY KEY, name TEXT NOT NULL, id TEXT NOT NULL,
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL, function_version INTEGER NOT NULL,
 key_arn TEXT NOT NULL, wrapped_key BLOB, encrypted BOOLEAN NOT NULL,
 status TEXT NOT NULL, input TEXT, result TEXT,
 started_at TIMESTAMP NOT NULL, ended_at TIMESTAMP NOT NULL, deadline TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL,
 execution_timeout INTEGER NOT NULL, retention_days INTEGER NOT NULL,
 token TEXT NOT NULL, generation INTEGER NOT NULL, claimed BOOLEAN NOT NULL, next_run_at TIMESTAMP NOT NULL,
 invocation_type TEXT NOT NULL, trace_id TEXT NOT NULL, client_context TEXT NOT NULL
);

CREATE TABLE lambda_durable_history (
 execution_arn TEXT NOT NULL, position INTEGER NOT NULL, id INTEGER NOT NULL, at TIMESTAMP NOT NULL, type TEXT NOT NULL,
 PRIMARY KEY(execution_arn,position),
 FOREIGN KEY(execution_arn) REFERENCES lambda_durable_executions(arn) ON DELETE CASCADE
);

-- Request contains canonical checkpoint input bytes for ClientToken comparison
-- (AEAD ciphertext for encrypted executions), never execution blobs or receipts.
CREATE TABLE lambda_durable_checkpoints (
 execution_arn TEXT NOT NULL, position INTEGER NOT NULL,
 client_token TEXT NOT NULL, previous_token TEXT NOT NULL, next_token TEXT NOT NULL,
 request BLOB, expires_at TIMESTAMP NOT NULL,
 PRIMARY KEY(execution_arn,position),
 FOREIGN KEY(execution_arn) REFERENCES lambda_durable_executions(arn) ON DELETE CASCADE
);

-- The same typed operation shape occurs in current state, history, and checkpoint
-- response snapshots. snapshot_position identifies its owning history/checkpoint.
CREATE TABLE lambda_durable_operations (
 execution_arn TEXT NOT NULL, collection TEXT NOT NULL CHECK(collection IN ('CURRENT','HISTORY','CHECKPOINT')),
 snapshot_position INTEGER NOT NULL, position INTEGER NOT NULL,
 id TEXT NOT NULL, parent_id TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL, sub_type TEXT NOT NULL, status TEXT NOT NULL,
 started_at TIMESTAMP NOT NULL, ended_at TIMESTAMP NOT NULL, due_at TIMESTAMP NOT NULL,
 payload TEXT, attempt INTEGER NOT NULL, replay_children BOOLEAN NOT NULL,
 callback_id TEXT NOT NULL, callback_timeout_at TIMESTAMP NOT NULL, heartbeat_at TIMESTAMP NOT NULL,
 heartbeat_seconds INTEGER NOT NULL, timeout_seconds INTEGER NOT NULL,
 target_function TEXT NOT NULL, target_tenant TEXT NOT NULL, generation INTEGER NOT NULL,
 PRIMARY KEY(execution_arn,collection,snapshot_position,position),
 FOREIGN KEY(execution_arn) REFERENCES lambda_durable_executions(arn) ON DELETE CASCADE
);

-- Absence distinguishes a nil error from a present error with nullable members.
CREATE TABLE lambda_durable_errors (
 execution_arn TEXT NOT NULL, collection TEXT NOT NULL CHECK(collection IN ('EXECUTION','CURRENT','HISTORY','CHECKPOINT')),
 snapshot_position INTEGER NOT NULL, position INTEGER NOT NULL,
 error_data TEXT, error_message TEXT, error_type TEXT, has_stack_trace BOOLEAN NOT NULL,
 PRIMARY KEY(execution_arn,collection,snapshot_position,position),
 FOREIGN KEY(execution_arn) REFERENCES lambda_durable_executions(arn) ON DELETE CASCADE
);
CREATE TABLE lambda_durable_error_frames (
 execution_arn TEXT NOT NULL, collection TEXT NOT NULL, snapshot_position INTEGER NOT NULL, operation_position INTEGER NOT NULL,
 position INTEGER NOT NULL, frame TEXT NOT NULL,
 PRIMARY KEY(execution_arn,collection,snapshot_position,operation_position,position),
 FOREIGN KEY(execution_arn,collection,snapshot_position,operation_position) REFERENCES lambda_durable_errors(execution_arn,collection,snapshot_position,position) ON DELETE CASCADE
);

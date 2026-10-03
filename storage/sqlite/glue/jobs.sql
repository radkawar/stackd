-- name: GetGlueJob :one
SELECT * FROM glue_jobs WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListGlueJobs :many
SELECT * FROM glue_jobs WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;

-- name: DeleteGlueJob :exec
DELETE FROM glue_jobs WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetGlueJobRun :one
SELECT * FROM glue_job_runs WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND id = ?;

-- name: ListGlueJobRuns :many
SELECT * FROM glue_job_runs WHERE partition = ? AND account_id = ? AND region = ? AND name = ? ORDER BY started_at DESC, id DESC;

-- name: PendingGlueJobRuns :many
SELECT * FROM glue_job_runs WHERE state IN ('STARTING','RUNNING','STOPPING') OR cleanup_pending = 1 OR published = 0 ORDER BY next_attempt, partition, account_id, region, name, id;

-- name: ListGlueJobAttempts :many
SELECT * FROM glue_job_attempts WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND id = ? ORDER BY attempt;

-- name: PutGlueJob :exec
INSERT INTO glue_jobs (partition, account_id, region, name, description, role, command, script_location, python_version, glue_version, worker_type, execution_class, security_configuration, max_concurrent_runs, max_retries, timeout, number_of_workers, max_capacity, default_arguments, non_overridable_arguments, tags, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET
    description = excluded.description,
    role = excluded.role,
    command = excluded.command,
    script_location = excluded.script_location,
    python_version = excluded.python_version,
    glue_version = excluded.glue_version,
    worker_type = excluded.worker_type,
    execution_class = excluded.execution_class,
    security_configuration = excluded.security_configuration,
    max_concurrent_runs = excluded.max_concurrent_runs,
    max_retries = excluded.max_retries,
    timeout = excluded.timeout,
    number_of_workers = excluded.number_of_workers,
    max_capacity = excluded.max_capacity,
    default_arguments = excluded.default_arguments,
    non_overridable_arguments = excluded.non_overridable_arguments,
    tags = excluded.tags,
    created_at = excluded.created_at,
    updated_at = excluded.updated_at;

-- name: PutGlueJobRun :exec
INSERT INTO glue_job_runs (partition, account_id, region, name, id, state, role, command, script_location, python_version, glue_version, worker_type, execution_class, security_configuration, previous_run_id, trigger_name, workflow_name, workflow_run_id, timeout, number_of_workers, attempt, max_capacity, arguments, started_at, updated_at, completed_at, next_attempt, version, launch_attempted, cleanup_pending, published, error, output, s3_encryption_mode, s3_kms_key, logs_kms_key, max_retries, run_arguments, retry_pending, metrics_published, log_error, metrics_observed, metrics_completed_tasks, metrics_failed_tasks, metrics_killed_tasks, metrics_completed_stages, metrics_bytes_read, metrics_records_read, error_output, execution_seconds)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name, id) DO UPDATE SET
    state = excluded.state,
    role = excluded.role,
    command = excluded.command,
    script_location = excluded.script_location,
    python_version = excluded.python_version,
    glue_version = excluded.glue_version,
    worker_type = excluded.worker_type,
    execution_class = excluded.execution_class,
    security_configuration = excluded.security_configuration,
    previous_run_id = excluded.previous_run_id,
    trigger_name = excluded.trigger_name,
    workflow_name = excluded.workflow_name,
    workflow_run_id = excluded.workflow_run_id,
    timeout = excluded.timeout,
    number_of_workers = excluded.number_of_workers,
    attempt = excluded.attempt,
    max_capacity = excluded.max_capacity,
    arguments = excluded.arguments,
    started_at = excluded.started_at,
    updated_at = excluded.updated_at,
    completed_at = excluded.completed_at,
    next_attempt = excluded.next_attempt,
    version = excluded.version,
    launch_attempted = excluded.launch_attempted,
    cleanup_pending = excluded.cleanup_pending,
    published = excluded.published,
    error = excluded.error,
    output = excluded.output,
    s3_encryption_mode = excluded.s3_encryption_mode,
    s3_kms_key = excluded.s3_kms_key,
    logs_kms_key = excluded.logs_kms_key,
    max_retries = excluded.max_retries,
    run_arguments = excluded.run_arguments,
    retry_pending = excluded.retry_pending,
    metrics_published = excluded.metrics_published,
    log_error = excluded.log_error,
    metrics_observed = excluded.metrics_observed,
    metrics_completed_tasks = excluded.metrics_completed_tasks,
    metrics_failed_tasks = excluded.metrics_failed_tasks,
    metrics_killed_tasks = excluded.metrics_killed_tasks,
    metrics_completed_stages = excluded.metrics_completed_stages,
    metrics_bytes_read = excluded.metrics_bytes_read,
    metrics_records_read = excluded.metrics_records_read,
    error_output = excluded.error_output,
    execution_seconds = excluded.execution_seconds;

-- name: PutGlueJobAttempt :exec
INSERT INTO glue_job_attempts (partition, account_id, region, name, id, attempt, state, error, output, error_output, started_at, completed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name, id, attempt) DO UPDATE SET
    state = excluded.state,
    error = excluded.error,
    output = excluded.output,
    error_output = excluded.error_output,
    started_at = excluded.started_at,
    completed_at = excluded.completed_at;


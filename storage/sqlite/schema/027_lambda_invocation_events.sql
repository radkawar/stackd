CREATE TABLE lambda_invocation_accepted_events (
    sequence INTEGER PRIMARY KEY REFERENCES kernel_events(sequence),
    invocation_id TEXT NOT NULL,
    function_arn TEXT NOT NULL
);

CREATE TABLE ssm_command_alarms (
    command_id INTEGER PRIMARY KEY REFERENCES ssm_commands(id) ON DELETE CASCADE,
    alarm_name TEXT NOT NULL,
    ignore_poll_failure BOOLEAN NOT NULL,
    role_id TEXT NOT NULL,
    due TIMESTAMP,
    revision INTEGER NOT NULL,
    checked BOOLEAN NOT NULL,
    triggered_state TEXT NOT NULL,
    last_error TEXT NOT NULL
);
CREATE INDEX ssm_command_alarms_due ON ssm_command_alarms(due, command_id) WHERE due IS NOT NULL;

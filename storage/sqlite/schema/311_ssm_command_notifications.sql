CREATE TABLE ssm_command_notification_config (
    command_id INTEGER PRIMARY KEY REFERENCES ssm_commands(id) ON DELETE CASCADE,
    service_role_arn TEXT NOT NULL,
    service_role_id TEXT NOT NULL,
    notification_arn TEXT NOT NULL,
    notification_type TEXT NOT NULL
);
CREATE TABLE ssm_command_notification_events (
    command_id INTEGER NOT NULL REFERENCES ssm_command_notification_config(command_id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    event TEXT NOT NULL,
    PRIMARY KEY (command_id, position)
);
CREATE TABLE ssm_command_notifications (
    id TEXT PRIMARY KEY,
    command_id INTEGER NOT NULL REFERENCES ssm_commands(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    status TEXT NOT NULL,
    status_details TEXT NOT NULL,
    event_time TIMESTAMP NOT NULL,
    due TIMESTAMP NOT NULL,
    revision INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    delivered_at TIMESTAMP,
    last_error TEXT NOT NULL
);
CREATE INDEX ssm_command_notifications_due ON ssm_command_notifications(due, id) WHERE message_id = '';

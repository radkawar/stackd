CREATE TABLE sns_message_encryption_context (
    message_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (message_id, protocol, name),
    FOREIGN KEY (message_id, protocol) REFERENCES sns_messages(id, protocol) ON DELETE CASCADE
);

-- Previously accepted keys were wrapped with only the topic ARN.
INSERT INTO sns_message_encryption_context (message_id, protocol, name, value)
SELECT id, protocol, 'aws:sns:topicArn',
    'arn:' || partition || ':sns:' || region || ':' || account_id || ':' || topic_name
FROM sns_messages WHERE kms_key_arn <> '';

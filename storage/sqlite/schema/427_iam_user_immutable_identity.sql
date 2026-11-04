-- Eventual IAM usage checks immutable user ownership without loading account state.
CREATE INDEX iam_user_immutable_identity ON iam_user(partition, account, user_id);

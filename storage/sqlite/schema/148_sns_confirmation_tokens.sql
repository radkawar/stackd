CREATE TABLE sns_confirmation_tokens_retained (
 token TEXT PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 topic_name TEXT NOT NULL,
 subscription_id TEXT NOT NULL,
 expires TIMESTAMP NOT NULL
);
INSERT INTO sns_confirmation_tokens_retained (token, partition, account_id, region, topic_name, subscription_id, expires)
SELECT c.token, s.partition, s.account_id, s.region, s.topic_name, s.id, c.expires
FROM sns_confirmation_tokens c JOIN sns_subscriptions s ON s.arn = c.subscription_arn;
DROP TABLE sns_confirmation_tokens;
ALTER TABLE sns_confirmation_tokens_retained RENAME TO sns_confirmation_tokens;
CREATE INDEX sns_confirmation_expiration ON sns_confirmation_tokens(expires);

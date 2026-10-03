ALTER TABLE sns_topics ADD COLUMN delivery_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_subscriptions ADD COLUMN state TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_subscriptions ADD COLUMN confirmation_authenticated BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE sns_subscriptions ADD COLUMN authenticate_on_unsubscribe BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sns_subscriptions ADD COLUMN subscription_role_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_subscriptions ADD COLUMN delivery_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_subscriptions ADD COLUMN next_http_delivery TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00+00:00';
ALTER TABLE sns_messages ADD COLUMN message_type TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_messages ADD COLUMN token TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_messages ADD COLUMN subscribe_url TEXT NOT NULL DEFAULT '';
CREATE TABLE sns_confirmation_tokens (
 token TEXT PRIMARY KEY,
 subscription_arn TEXT NOT NULL REFERENCES sns_subscriptions(arn) ON DELETE CASCADE,
 expires TIMESTAMP NOT NULL
);
CREATE INDEX sns_confirmation_subscription ON sns_confirmation_tokens(subscription_arn);

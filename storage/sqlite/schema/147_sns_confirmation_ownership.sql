-- Earlier AWS endpoint subscriptions were always automatically confirmed.
-- Preserve their owner-only deletion when manual SQS confirmation is introduced.
UPDATE sns_subscriptions SET authenticate_on_unsubscribe = TRUE
WHERE protocol NOT IN ('http', 'https');

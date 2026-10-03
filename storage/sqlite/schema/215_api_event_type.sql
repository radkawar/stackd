-- Public API event types remain source-owned; empty retains the existing
-- AwsApiCall/AwsServiceEvent projection for every previous producer.
ALTER TABLE api_call_events ADD COLUMN cloudtrail_event_type TEXT NOT NULL DEFAULT '';

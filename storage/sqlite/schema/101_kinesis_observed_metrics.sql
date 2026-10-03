-- Kinesis publishes observed request/event samples, not synthetic idle zeros.
DROP INDEX kinesis_streams_metrics_due;
ALTER TABLE kinesis_streams DROP COLUMN metrics_next_at;

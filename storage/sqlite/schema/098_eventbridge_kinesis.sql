-- NULL means the documented event-ID default; configured paths are retained
-- with each delivery independently of later target edits or deletion.
ALTER TABLE eventbridge_targets ADD COLUMN kinesis_partition_key_path TEXT;
ALTER TABLE eventbridge_deliveries ADD COLUMN kinesis_partition_key_path TEXT;

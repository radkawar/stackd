ALTER TABLE firehose_buffers ADD COLUMN kind TEXT NOT NULL DEFAULT '';
CREATE INDEX firehose_buffer_open_output ON firehose_buffers(stream_id, stream_version, kind, created, id) WHERE object_key = '';

ALTER TABLE firehose_records ADD COLUMN original_bytes INTEGER NOT NULL DEFAULT 0;
UPDATE firehose_records SET original_bytes = coalesce(length(data), 0);
ALTER TABLE firehose_records ADD COLUMN kinesis_shard_id TEXT;
ALTER TABLE firehose_records ADD COLUMN kinesis_partition_key TEXT;
ALTER TABLE firehose_records ADD COLUMN kinesis_sequence_number TEXT;

CREATE TABLE firehose_processing (
    buffer_id TEXT PRIMARY KEY REFERENCES firehose_buffers(id) ON DELETE CASCADE,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    due DATETIME NOT NULL
);
CREATE INDEX firehose_processing_due ON firehose_processing(due, buffer_id) WHERE state = 'queued';
CREATE INDEX firehose_processing_in_flight ON firehose_processing(buffer_id) WHERE state = 'in-flight';

-- A backup reuses the destination columns and belongs to its primary configuration.
ALTER TABLE firehose_configurations ADD COLUMN parent_configuration_id TEXT REFERENCES firehose_configurations(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX firehose_configuration_backup ON firehose_configurations(parent_configuration_id) WHERE parent_configuration_id IS NOT NULL;

-- Remove the local-only SQS processing-result status. Failures are diagnosed
-- through source operation logs and existing invocation counters.
ALTER TABLE lambda_event_source_mappings DROP COLUMN last_processing_result;

ALTER TABLE lambda_invocations ADD COLUMN settings_detached BOOLEAN NOT NULL DEFAULT false;
-- Older controllers retained accepted work after deletion without an explicit
-- detachment marker. Only an absent scoped root proves that transition; a
-- surviving function or an already completed result must keep its ownership.
UPDATE lambda_invocations AS invocation SET settings_detached=true
WHERE invocation.state != 'completed' AND NOT EXISTS (
    SELECT 1 FROM lambda_functions AS function
    WHERE function.partition=invocation.partition AND function.account=invocation.account
      AND function.region=invocation.region AND function.name=invocation.function_name
      AND function.pending=false AND function.version=0
);
CREATE INDEX lambda_invocations_function ON lambda_invocations(partition,account,region,function_name) WHERE state != 'completed';

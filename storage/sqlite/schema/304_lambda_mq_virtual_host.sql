ALTER TABLE lambda_mq_mappings ADD COLUMN virtual_host_set BOOLEAN NOT NULL DEFAULT FALSE;

-- Earlier state retained custom hosts but did not distinguish an explicit '/'
-- from the implicit default. Preserve its former projection rather than inventing
-- an explicit root-host request that was not recorded.
UPDATE lambda_mq_mappings SET virtual_host_set = TRUE WHERE virtual_host <> '/';

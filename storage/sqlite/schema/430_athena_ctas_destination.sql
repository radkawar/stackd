-- Workgroup output enforcement is fixed when a query is admitted, not read from
-- a potentially changed workgroup when the native worker eventually executes.
ALTER TABLE athena_queries ADD COLUMN enforce_ctas_destination BOOLEAN NOT NULL DEFAULT 0;

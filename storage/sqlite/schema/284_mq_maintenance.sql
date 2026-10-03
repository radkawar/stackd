-- Earlier controllers did not retain maintenance adjustment counts. Start their
-- first tracked cycle at zero without replacing any broker or pending intent.
ALTER TABLE mq_brokers ADD COLUMN maintenance_adjustments INTEGER NOT NULL DEFAULT 0 CHECK (maintenance_adjustments BETWEEN 0 AND 4);

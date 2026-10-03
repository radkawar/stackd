ALTER TABLE eventbridge_targets ADD COLUMN input_value TEXT;
UPDATE eventbridge_targets SET input_value=input WHERE has_input;
ALTER TABLE eventbridge_targets DROP COLUMN input;
ALTER TABLE eventbridge_targets DROP COLUMN has_input;
ALTER TABLE eventbridge_targets RENAME COLUMN input_value TO input;
ALTER TABLE eventbridge_targets ADD COLUMN input_path TEXT;
ALTER TABLE eventbridge_targets ADD COLUMN input_template TEXT;

CREATE TABLE eventbridge_target_input_paths (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
    bus_name TEXT NOT NULL, rule_name TEXT NOT NULL, target_id TEXT NOT NULL,
    key TEXT NOT NULL, path TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, bus_name, rule_name, target_id, key),
    FOREIGN KEY (partition, account, region, bus_name, rule_name, target_id)
        REFERENCES eventbridge_targets(partition, account, region, bus_name, rule_name, id) ON DELETE CASCADE
);

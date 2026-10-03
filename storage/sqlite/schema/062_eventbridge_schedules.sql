ALTER TABLE eventbridge_rules ADD COLUMN has_pattern BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE eventbridge_rules ADD COLUMN has_description BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE eventbridge_rules SET has_description = description <> '';
ALTER TABLE eventbridge_rules ADD COLUMN schedule_expression TEXT;
ALTER TABLE eventbridge_rules ADD COLUMN next_schedule_seconds INTEGER;

CREATE INDEX eventbridge_rules_schedule_due ON eventbridge_rules (
    next_schedule_seconds,
    'arn:' || partition || ':events:' || region || ':' || account || ':rule/' || CASE WHEN bus_name='default' THEN name ELSE bus_name || '/' || name END
) WHERE next_schedule_seconds IS NOT NULL;

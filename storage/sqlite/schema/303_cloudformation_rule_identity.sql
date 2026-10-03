-- EventBridge custom-bus CloudFormation identities are bus|rule, not rule.
-- Preserve historical emitted events and output/export values; subsequent stack
-- operations evaluate outputs from the corrected resource references. Upgrade
-- retained before/after images too so recovery never reintroduces the old IDs.
WITH rule_names AS (
    SELECT rowid AS id, physical_id AS name,
           COALESCE(json_extract(properties, '$.EventBusName'), 'default') AS bus
    FROM cloudformation_resources
    WHERE type = 'AWS::Events::Rule' AND physical_id <> '' AND instr(physical_id, '|') = 0
), rule_ids AS (
    SELECT id, name,
           CASE WHEN instr(bus, ':event-bus/') > 0 THEN substr(bus, instr(bus, ':event-bus/') + 11) ELSE bus END AS bus
    FROM rule_names
)
UPDATE cloudformation_resources AS resource
SET physical_id = CASE WHEN rule.bus = 'default' THEN rule.name ELSE rule.bus || '|' || rule.name END,
    ref = CASE WHEN rule.bus = 'default' THEN rule.name ELSE rule.bus || '|' || rule.name END,
    attributes = json_set(resource.attributes, '$.RuleName', rule.name)
FROM rule_ids AS rule
WHERE resource.rowid = rule.id;

WITH rule_names AS (
    SELECT rowid AS id, before_physical_id AS name,
           COALESCE(json_extract(before_properties, '$.EventBusName'), 'default') AS bus
    FROM cloudformation_steps
    WHERE before_type = 'AWS::Events::Rule' AND before_physical_id <> '' AND instr(before_physical_id, '|') = 0
), rule_ids AS (
    SELECT id, name,
           CASE WHEN instr(bus, ':event-bus/') > 0 THEN substr(bus, instr(bus, ':event-bus/') + 11) ELSE bus END AS bus
    FROM rule_names
)
UPDATE cloudformation_steps AS step
SET before_physical_id = CASE WHEN rule.bus = 'default' THEN rule.name ELSE rule.bus || '|' || rule.name END,
    before_ref = CASE WHEN rule.bus = 'default' THEN rule.name ELSE rule.bus || '|' || rule.name END,
    before_attributes = json_set(step.before_attributes, '$.RuleName', rule.name)
FROM rule_ids AS rule
WHERE step.rowid = rule.id;

WITH rule_names AS (
    SELECT rowid AS id, after_physical_id AS name,
           COALESCE(json_extract(after_properties, '$.EventBusName'), 'default') AS bus
    FROM cloudformation_steps
    WHERE after_type = 'AWS::Events::Rule' AND after_physical_id <> '' AND instr(after_physical_id, '|') = 0
), rule_ids AS (
    SELECT id, name,
           CASE WHEN instr(bus, ':event-bus/') > 0 THEN substr(bus, instr(bus, ':event-bus/') + 11) ELSE bus END AS bus
    FROM rule_names
)
UPDATE cloudformation_steps AS step
SET after_physical_id = CASE WHEN rule.bus = 'default' THEN rule.name ELSE rule.bus || '|' || rule.name END,
    after_ref = CASE WHEN rule.bus = 'default' THEN rule.name ELSE rule.bus || '|' || rule.name END,
    after_attributes = json_set(step.after_attributes, '$.RuleName', rule.name)
FROM rule_ids AS rule
WHERE step.rowid = rule.id;

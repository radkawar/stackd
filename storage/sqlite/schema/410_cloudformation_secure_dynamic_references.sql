-- Replace ordinary SSM numeric selectors with the typed service/version format.
-- All retained before/after/restoration images must replay the same version.
UPDATE cloudformation_resources
SET dynamic_references = (
    SELECT json_group_object(key, json_object('service', 'ssm', 'parameter_version', value))
    FROM json_each(cloudformation_resources.dynamic_references)
)
WHERE EXISTS (SELECT 1 FROM json_each(dynamic_references) WHERE type = 'integer');

UPDATE cloudformation_steps
SET before_dynamic_references = (
    SELECT json_group_object(key, json_object('service', 'ssm', 'parameter_version', value))
    FROM json_each(cloudformation_steps.before_dynamic_references)
)
WHERE EXISTS (SELECT 1 FROM json_each(before_dynamic_references) WHERE type = 'integer');

UPDATE cloudformation_steps
SET after_dynamic_references = (
    SELECT json_group_object(key, json_object('service', 'ssm', 'parameter_version', value))
    FROM json_each(cloudformation_steps.after_dynamic_references)
)
WHERE EXISTS (SELECT 1 FROM json_each(after_dynamic_references) WHERE type = 'integer');

UPDATE cloudformation_steps
SET restore_dynamic_references = (
    SELECT json_group_object(key, json_object('service', 'ssm', 'parameter_version', value))
    FROM json_each(cloudformation_steps.restore_dynamic_references)
)
WHERE EXISTS (SELECT 1 FROM json_each(restore_dynamic_references) WHERE type = 'integer');

-- Attribute masks are projections, never intrinsic values. Retain the typed
-- consumption guard on every current and operation-local resource image.
ALTER TABLE cloudformation_resources ADD COLUMN redacted_attributes TEXT NOT NULL DEFAULT '{}';
ALTER TABLE cloudformation_steps ADD COLUMN before_redacted_attributes TEXT NOT NULL DEFAULT '{}';
ALTER TABLE cloudformation_steps ADD COLUMN after_redacted_attributes TEXT NOT NULL DEFAULT '{}';
ALTER TABLE cloudformation_steps ADD COLUMN restore_redacted_attributes TEXT NOT NULL DEFAULT '{}';

-- Native resource claims are independent of customer tags and public payloads.
ALTER TABLE appconfig_applications ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_applications ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_environments ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_environments ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_profiles ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_profiles ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_hosted_versions ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_hosted_versions ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_strategies ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_strategies ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_deployments ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_deployments ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_extensions ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_extensions ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_associations ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_associations ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_experiment_definitions ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_experiment_definitions ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_experiment_runs ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE appconfig_experiment_runs ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';

-- Hosted versions were never publicly taggable. Preserve only their previously
-- private internal bindings; public taggable resources deliberately stay unclaimed.
UPDATE appconfig_hosted_versions AS v SET
 cfn_owner = COALESCE((SELECT value FROM appconfig_tags AS t WHERE t.partition=v.partition AND t.account_id=v.account_id AND t.region=v.region AND t.arn='arn:'||v.partition||':appconfig:'||v.region||':'||v.account_id||':application/'||v.application_id||'/configurationprofile/'||v.profile_id||'/hostedconfigurationversion/'||v.number AND t.key='stackd:cloudformation:owner'), ''),
 cfn_token = COALESCE((SELECT value FROM appconfig_tags AS t WHERE t.partition=v.partition AND t.account_id=v.account_id AND t.region=v.region AND t.arn='arn:'||v.partition||':appconfig:'||v.region||':'||v.account_id||':application/'||v.application_id||'/configurationprofile/'||v.profile_id||'/hostedconfigurationversion/'||v.number AND t.key='stackd:cloudformation:create-token'), '');
DELETE FROM appconfig_tags WHERE key IN ('stackd:cloudformation:owner','stackd:cloudformation:create-token') AND arn LIKE '%/hostedconfigurationversion/%';

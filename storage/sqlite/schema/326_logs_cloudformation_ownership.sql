ALTER TABLE logs_streams ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE logs_metric_filters ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE logs_subscriptions ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE logs_resource_policies ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';

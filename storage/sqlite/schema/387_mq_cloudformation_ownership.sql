-- Private CloudFormation incarnation claims for brokers and configurations.
-- Public broker/configuration tags never carry ownership; empty is unowned.
ALTER TABLE mq_brokers ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE mq_configurations ADD COLUMN ownership TEXT NOT NULL DEFAULT '';

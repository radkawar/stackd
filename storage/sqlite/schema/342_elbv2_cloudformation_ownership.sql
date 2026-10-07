-- Private native-row CloudFormation incarnation claims are not public tags.
ALTER TABLE elbv2_load_balancers ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE elbv2_target_groups ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE elbv2_listeners ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE elbv2_rules ADD COLUMN ownership TEXT NOT NULL DEFAULT '';

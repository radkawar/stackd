-- Private native-row CloudFormation incarnation claims are not public tags.
ALTER TABLE asg_groups ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE asg_hooks ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE asg_policies ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE asg_schedules ADD COLUMN ownership TEXT NOT NULL DEFAULT '';

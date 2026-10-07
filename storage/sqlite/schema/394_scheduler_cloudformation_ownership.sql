ALTER TABLE scheduler_groups ADD COLUMN id TEXT NOT NULL DEFAULT '';
ALTER TABLE scheduler_groups ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE scheduler_schedules ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE scheduler_schedules ADD COLUMN parent_id TEXT NOT NULL DEFAULT '';
UPDATE scheduler_groups SET id = lower(hex(randomblob(16)));
UPDATE scheduler_schedules SET parent_id = COALESCE((SELECT g.id FROM scheduler_groups g WHERE g.partition = scheduler_schedules.partition AND g.account = scheduler_schedules.account AND g.region = scheduler_schedules.region AND g.name = scheduler_schedules.group_name), '');

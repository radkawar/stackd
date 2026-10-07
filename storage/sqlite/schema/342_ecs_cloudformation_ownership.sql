-- Private native-row CloudFormation incarnation claims are not public tags.
ALTER TABLE ecs_clusters ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE ecs_task_definitions ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE ecs_services ADD COLUMN ownership TEXT NOT NULL DEFAULT '';

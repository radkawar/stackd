-- Private CloudFormation repository incarnation claims are not public tags.
ALTER TABLE ecr_repositories ADD COLUMN ownership TEXT NOT NULL DEFAULT '';

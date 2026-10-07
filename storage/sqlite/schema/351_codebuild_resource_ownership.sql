ALTER TABLE codebuild_projects ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE codebuild_fleets ADD COLUMN ownership TEXT NOT NULL DEFAULT '';

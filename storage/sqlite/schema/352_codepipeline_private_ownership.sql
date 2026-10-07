ALTER TABLE codepipeline_pipelines ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE codepipeline_pipelines ADD COLUMN last_update TEXT NOT NULL DEFAULT '';

ALTER TABLE eks_nodegroup ADD COLUMN scale_down_started INTEGER NOT NULL DEFAULT 0;
ALTER TABLE eks_nodegroup ADD COLUMN scale_down_scale_up_version INTEGER NOT NULL DEFAULT 0;

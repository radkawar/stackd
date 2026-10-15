ALTER TABLE logs_groups ADD COLUMN deletion_protected INTEGER NOT NULL DEFAULT 0 CHECK (deletion_protected IN (0, 1));

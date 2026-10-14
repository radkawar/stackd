-- Requested GiB only: native bytes remain on the Docker host's volume filesystem.
-- Zero preserves the unknown capacity of existing databases/snapshots.
ALTER TABLE rds_database ADD COLUMN allocated_storage INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rds_snapshot ADD COLUMN allocated_storage INTEGER NOT NULL DEFAULT 0;

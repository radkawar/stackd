-- Retained service-time intent for real cold native backups, not continuous PITR.
ALTER TABLE docdb_cluster ADD COLUMN backup_retention INTEGER NOT NULL DEFAULT 1;
ALTER TABLE docdb_cluster ADD COLUMN backup_window TEXT NOT NULL DEFAULT '09:00-09:30';
ALTER TABLE docdb_cluster ADD COLUMN next_backup INTEGER NOT NULL DEFAULT 0;
ALTER TABLE docdb_snapshot ADD COLUMN automated INTEGER NOT NULL DEFAULT 0;
ALTER TABLE docdb_snapshot ADD COLUMN expires INTEGER NOT NULL DEFAULT 0;

package docdb

import (
	"context"
	"errors"
	"maps"
	"strings"
	"time"

	"stackd/internal/scheduler"
)

const defaultBackupWindow = "09:00-09:30"

// AWS retains automated backups for 1–35 days and requires a UTC window of at
// least 30 minutes. This adapter takes one real cold snapshot per daily window;
// it does not implement AWS's continuous, online point-in-time backup storage.
// https://docs.aws.amazon.com/documentdb/latest/APIReference/API_CreateDBCluster.html
// https://docs.aws.amazon.com/documentdb/latest/devguide/backup_restore.html
func validateBackups(retention int32, window string) error {
	if retention < 1 || retention > 35 {
		return failure("InvalidParameterValue", "BackupRetentionPeriod must be between 1 and 35 days.")
	}
	parts := strings.Split(window, "-")
	if len(parts) != 2 {
		return failure("InvalidParameterValue", "PreferredBackupWindow must use hh24:mi-hh24:mi in UTC.")
	}
	start, e := time.Parse("15:04", parts[0])
	end, endErr := time.Parse("15:04", parts[1])
	if e != nil || endErr != nil || len(parts[0]) != 5 || len(parts[1]) != 5 {
		return failure("InvalidParameterValue", "PreferredBackupWindow must use hh24:mi-hh24:mi in UTC.")
	}
	duration := end.Sub(start)
	if duration < 0 {
		duration += 24 * time.Hour
	}
	if duration < 30*time.Minute {
		return failure("InvalidParameterValue", "PreferredBackupWindow must be at least 30 minutes.")
	}
	return nil
}

func nextBackup(now time.Time, window string) time.Time {
	start, _ := time.Parse("15:04", strings.Split(window, "-")[0])
	now = now.UTC()
	candidate := time.Date(now.Year(), now.Month(), now.Day(), start.Hour(), start.Minute(), 0, 0, time.UTC)
	if !candidate.After(now) {
		candidate = candidate.Add(24 * time.Hour)
	}
	return candidate
}

type backupJobs struct{ s *Service }

func (j backupJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		all, err := r.Clusters()
		if err != nil {
			return err
		}
		for _, v := range all {
			if v.BackupRetention == 0 || v.NextBackup.IsZero() || v.Status != "available" || v.Operation != "" || v.Endpoint.Address == "" {
				continue
			}
			candidate := scheduler.Job{Key: "backup|" + v.Key.ARN(), Version: uint64(v.Version), Due: v.NextBackup}
			if !found || scheduler.Compare(candidate, next) < 0 {
				next, found = candidate, true
			}
		}
		return nil
	})
	return next, found, err
}

func (j backupJobs) Run(ctx context.Context, job scheduler.Job) error {
	k, err := jobKey(strings.TrimPrefix(job.Key, "backup|"))
	if err != nil {
		return err
	}
	ctx = runtimeContext(ctx, k)
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		v, err := tx.Cluster(k)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		now := j.s.clock.Now()
		if uint64(v.Version) != job.Version || !v.NextBackup.Equal(job.Due) || v.NextBackup.After(now) || v.BackupRetention == 0 || v.Status != "available" || v.Operation != "" || v.Endpoint.Address == "" {
			return nil
		}
		members, err := membersOf(tx, v)
		if err != nil {
			return err
		}
		if len(members) != 1 || members[0].Status != "available" {
			return nil
		}
		// The native snapshot incarnation is retained by captureSnapshot. Missed
		// windows produce one current snapshot, never invented historical copies.
		snapshotKey := Key{Scope: v.Key.Scope, Kind: "cluster-snapshot", Name: "auto-" + v.RuntimeID + "-" + job.Due.UTC().Format("200601021504")}
		if _, err := tx.Snapshot(snapshotKey); err == nil {
			return errors.New("automated snapshot ownership already exists without its schedule transition")
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		v.NextBackup = nextBackup(now, v.BackupWindow)
		_, err = j.s.captureSnapshot(tx.Context(), tx, v, snapshotKey, maps.Clone(v.Tags), true)
		return err
	})
}

// expireSnapshot retains retirement before the native DeleteSnapshot effect and
// waits for restore consumers to release the immutable source incarnation.
func (s *Service) expireSnapshot(ctx context.Context, snap Snapshot) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Snapshot(snap.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != snap.Version || current.RuntimeID != snap.RuntimeID || !current.Automated || current.Operation != "" || current.Expires.After(s.clock.Now()) {
			return nil
		}
		clusters, err := tx.Clusters()
		if err != nil {
			return err
		}
		for _, v := range clusters {
			if v.Key.Scope == current.Key.Scope && v.RestoreSnapshot == current.RuntimeID {
				current.Due = s.clock.Now().Add(healthInterval)
				current.Version++
				return tx.PutSnapshot(current)
			}
		}
		current.Status, current.Operation = "deleting", "delete"
		current.Due = s.clock.Now()
		current.Version++
		return tx.PutSnapshot(current)
	})
}

func (s *Service) changeBackups(tx Transaction, v *Cluster, retention int32, window string) error {
	all, err := tx.Snapshots()
	if err != nil {
		return err
	}
	for _, snap := range all {
		if !snap.Automated || snap.Key.Scope != v.Key.Scope || snap.SourceRuntimeID != v.RuntimeID || snap.Operation == "delete" {
			continue
		}
		snap.Expires = snap.Created.Add(time.Duration(retention) * 24 * time.Hour)
		if snap.Operation == "" {
			snap.Due = snap.Expires
		}
		snap.Version++
		if err := tx.PutSnapshot(snap); err != nil {
			return err
		}
	}
	if window != v.BackupWindow || v.NextBackup.IsZero() {
		v.NextBackup = nextBackup(s.clock.Now(), window)
	}
	v.BackupRetention, v.BackupWindow = retention, window
	return nil
}

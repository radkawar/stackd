package dynamodb

import (
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/dynamodb"
)

func cloneBackupRecord(v BackupRecord) BackupRecord {
	v.Description = api.CloneBackupDescription(v.Description)
	v.AttributeDefinitions = api.CloneAttributeDefinitions(v.AttributeDefinitions)
	return v
}

func (r memoryReader) Backup(k BackupKey) (BackupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return BackupRecord{}, err
	}
	v, ok := r.s.backups[k]
	if !ok {
		return BackupRecord{}, ErrNotFound
	}
	return cloneBackupRecord(v), nil
}

func (r memoryReader) Backups(q BackupQuery) ([]BackupRecord, error) {
	return r.selectBackups(func(v BackupRecord) bool {
		details := v.Description.BackupDetails
		at := *details.BackupCreationDateTime
		return v.Key.Scope == q.Scope && value(details.BackupStatus) != "DELETED" && !backupExpired(&v, q.At) &&
			(q.Type == "" || value(details.BackupType) == q.Type) &&
			(q.TableName == "" || v.Key.TableName == q.TableName) && value(details.BackupArn) > q.After &&
			(q.Lower.IsZero() || !at.Before(q.Lower)) && (q.Upper.IsZero() || !at.After(q.Upper))
	}, q.Limit)
}

func (r memoryReader) PendingBackups(now time.Time) ([]BackupRecord, error) {
	return r.selectBackups(func(v BackupRecord) bool {
		return value(v.Description.BackupDetails.BackupStatus) != "AVAILABLE" || backupExpired(&v, now)
	}, 0)
}

func (r memoryReader) NextBackupExpiry(after time.Time) (time.Time, error) {
	if err := r.tx.Check(false); err != nil {
		return time.Time{}, err
	}
	var next time.Time
	for _, v := range r.s.backups {
		details := v.Description.BackupDetails
		expiry := details.BackupExpiryDateTime
		if value(details.BackupStatus) != "DELETED" && expiry != nil && expiry.After(after) && (next.IsZero() || expiry.Before(next)) {
			next = *expiry
		}
	}
	return next, nil
}

func (r memoryReader) UncapturedBackups(databaseID string) ([]BackupRecord, error) {
	return r.selectBackups(func(v BackupRecord) bool {
		return v.DatabaseID == databaseID && value(v.Description.BackupDetails.BackupStatus) == "CREATING"
	}, 0)
}

func (r memoryReader) HasDatabaseBackups(databaseID string) (bool, error) {
	if err := r.tx.Check(false); err != nil {
		return false, err
	}
	for _, v := range r.s.backups {
		if v.DatabaseID == databaseID {
			return true, nil
		}
	}
	return false, nil
}

func (r memoryReader) selectBackups(match func(BackupRecord) bool, limit int) ([]BackupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []BackupRecord
	for _, v := range r.s.backups {
		if match(v) {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b BackupRecord) int {
		return strings.Compare(value(a.Description.BackupDetails.BackupArn), value(b.Description.BackupDetails.BackupArn))
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit:limit]
	}
	for i := range out {
		out[i] = cloneBackupRecord(out[i])
	}
	return out, nil
}

func (w memoryWriter) PutBackup(v BackupRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.backups[v.Key] = cloneBackupRecord(v)
	return nil
}

func (w memoryWriter) DeleteBackup(k BackupKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.backups, k)
	return nil
}

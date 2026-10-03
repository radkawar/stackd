package eventbridge

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/eventbridge"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/eventbridge/internal/sqlcgen"
)

func archive(v sqlcgen.EventbridgeArchive) domain.ArchiveRecord {
	out := domain.ArchiveRecord{
		Key:         domain.ArchiveKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.Name},
		ID:          v.ID,
		Source:      domain.BusKey{Scope: domain.Scope{Partition: v.SourcePartition, Account: v.SourceAccount, Region: v.SourceRegion}, Name: v.SourceBusName},
		Description: v.Description, KmsKeyIdentifier: v.KmsKeyIdentifier, KeyARN: v.KeyArn,
		Pattern:       domain.ArchivePayload{Content: v.PatternContent, DataKey: v.PatternDataKey},
		RetentionDays: int32(v.RetentionDays), Created: v.Created, State: v.State, StateReason: v.StateReason,
		Version: uint64(v.Version), EventCount: v.EventCount, SizeBytes: v.SizeBytes,
		KeyVersion:     uint64(v.KeyVersion),
		PreviousKeyARN: v.PreviousKeyArn, PreviousKmsKeyIdentifier: v.PreviousKmsKeyIdentifier,
	}
	if v.MigrationDueSeconds.Valid {
		out.MigrationDue = time.Unix(v.MigrationDueSeconds.Int64, v.MigrationDueNanos).UTC()
	}
	return out
}

func (r reader) Archive(k domain.ArchiveKey) (domain.ArchiveRecord, error) {
	v, err := r.q.GetArchive(r.ctx, sqlcgen.GetArchiveParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.ArchiveRecord{}, missing(err)
	}
	return archive(v), nil
}

func (r reader) ArchiveByID(id string) (domain.ArchiveRecord, error) {
	v, err := r.q.GetArchiveByID(r.ctx, id)
	if err != nil {
		return domain.ArchiveRecord{}, missing(err)
	}
	return archive(v), nil
}

func (r reader) Archives(scope domain.Scope) ([]domain.ArchiveRecord, error) {
	rows, err := r.q.ListArchives(r.ctx, sqlcgen.ListArchivesParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ArchiveRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, archive(v))
	}
	return out, nil
}

func archiveEntry(v sqlcgen.EventbridgeArchiveEntry) domain.ArchiveEntry {
	out := domain.ArchiveEntry{
		ArchiveID: v.ArchiveID, ID: v.ID,
		Time:     time.Unix(v.EventSeconds, v.EventNanos).UTC(),
		Ingested: time.Unix(v.IngestedSeconds, v.IngestedNanos).UTC(),
		Payload:  domain.ArchivePayload{Content: v.Content, DataKey: v.DataKey}, SizeBytes: v.SizeBytes,
		KeyVersion: uint64(v.KeyVersion), RuleContext: v.RuleContext,
	}
	if v.ExpiresSeconds.Valid {
		out.Expires = time.Unix(v.ExpiresSeconds.Int64, v.ExpiresNanos).UTC()
	}
	return out
}

func (r reader) ArchiveEntry(archiveID, eventID string) (domain.ArchiveEntry, error) {
	v, err := r.q.GetArchiveEntry(r.ctx, sqlcgen.GetArchiveEntryParams{ArchiveID: archiveID, ID: eventID})
	if err != nil {
		return domain.ArchiveEntry{}, missing(err)
	}
	return archiveEntry(v), nil
}

func (r reader) NextArchiveEntry(archiveID string, start, end time.Time, after domain.ArchiveCursor) (domain.ArchiveEntry, bool, error) {
	v, err := r.q.NextArchiveEntry(r.ctx, sqlcgen.NextArchiveEntryParams{
		ArchiveID: archiveID, StartSeconds: start.Unix(), StartNanos: int64(start.Nanosecond()),
		EndSeconds: end.Unix(), EndNanos: int64(end.Nanosecond()),
		AfterID: after.ID, AfterSeconds: after.Time.Unix(), AfterNanos: int64(after.Time.Nanosecond()),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ArchiveEntry{}, false, nil
	}
	if err != nil {
		return domain.ArchiveEntry{}, false, err
	}
	return archiveEntry(v), true, nil
}

func (r reader) NextArchiveExpiration() (domain.ArchiveEntry, bool, error) {
	v, err := r.q.NextArchiveExpiration(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ArchiveEntry{}, false, nil
	}
	if err != nil {
		return domain.ArchiveEntry{}, false, err
	}
	return archiveEntry(v), true, nil
}

func (r reader) NextArchiveMigration() (domain.ArchiveRecord, bool, error) {
	v, err := r.q.NextArchiveMigration(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ArchiveRecord{}, false, nil
	}
	if err != nil {
		return domain.ArchiveRecord{}, false, err
	}
	return archive(v), true, nil
}

func (r reader) NextArchiveMigrationEntry(archiveID string, keyVersion uint64) (domain.ArchiveEntry, bool, error) {
	v, err := r.q.NextArchiveMigrationEntry(r.ctx, sqlcgen.NextArchiveMigrationEntryParams{ArchiveID: archiveID, KeyVersion: sqlite.Uint64(keyVersion)})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ArchiveEntry{}, false, nil
	}
	if err != nil {
		return domain.ArchiveEntry{}, false, err
	}
	return archiveEntry(v), true, nil
}

// SQL BLOB NOT NULL represents an absent data key as an empty byte sequence.
// database/sql detaches scanned []byte values; no second payload copy is needed.
func archiveBytes(v []byte) []byte {
	if v == nil {
		return []byte{}
	}
	return v
}

func archiveOptionalSeconds(v time.Time) sql.NullInt64 {
	if v.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: v.Unix(), Valid: true}
}

func (w writer) PutArchive(v domain.ArchiveRecord) error {
	k := v.Key
	return w.q.PutArchive(w.ctx, sqlcgen.PutArchiveParams{
		Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name, ID: v.ID,
		SourcePartition: v.Source.Partition, SourceAccount: v.Source.Account, SourceRegion: v.Source.Region, SourceBusName: v.Source.Name,
		Description: v.Description, KmsKeyIdentifier: v.KmsKeyIdentifier, KeyArn: v.KeyARN,
		PatternContent: archiveBytes(v.Pattern.Content), PatternDataKey: archiveBytes(v.Pattern.DataKey),
		RetentionDays: int64(v.RetentionDays), Created: v.Created, State: v.State, StateReason: v.StateReason,
		Version: sqlite.Uint64(v.Version), EventCount: v.EventCount, SizeBytes: v.SizeBytes,
		KeyVersion: sqlite.Uint64(v.KeyVersion), MigrationDueSeconds: archiveOptionalSeconds(v.MigrationDue), MigrationDueNanos: int64(v.MigrationDue.Nanosecond()),
		PreviousKeyArn: v.PreviousKeyARN, PreviousKmsKeyIdentifier: v.PreviousKmsKeyIdentifier,
	})
}

func (w writer) DeleteArchive(k domain.ArchiveKey) error {
	return w.q.DeleteArchive(w.ctx, sqlcgen.DeleteArchiveParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
}

func (w writer) PutArchiveEntry(v domain.ArchiveEntry) error {
	return w.q.PutArchiveEntry(w.ctx, sqlcgen.PutArchiveEntryParams{
		ArchiveID: v.ArchiveID, ID: v.ID, EventSeconds: v.Time.Unix(), EventNanos: int64(v.Time.Nanosecond()),
		IngestedSeconds: v.Ingested.Unix(), IngestedNanos: int64(v.Ingested.Nanosecond()),
		ExpiresSeconds: archiveOptionalSeconds(v.Expires), ExpiresNanos: int64(v.Expires.Nanosecond()),
		Content: archiveBytes(v.Payload.Content), DataKey: archiveBytes(v.Payload.DataKey), SizeBytes: v.SizeBytes,
		KeyVersion: sqlite.Uint64(v.KeyVersion), RuleContext: v.RuleContext,
	})
}

func (w writer) DeleteArchiveEntry(archiveID, eventID string) error {
	return w.q.DeleteArchiveEntry(w.ctx, sqlcgen.DeleteArchiveEntryParams{ArchiveID: archiveID, ID: eventID})
}

func (w writer) UpdateArchiveEntryRetention(archiveID string, days int32) error {
	return w.q.UpdateArchiveEntryRetention(w.ctx, sqlcgen.UpdateArchiveEntryRetentionParams{ArchiveID: archiveID, Days: int64(days)})
}

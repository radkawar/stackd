package sns

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/sns"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/sns/internal/sqlcgen"
)

func archiveEntry(v sqlcgen.SnsArchiveEntry) domain.ArchiveEntry {
	return domain.ArchiveEntry{
		TopicID: v.TopicID, Message: domain.MessageKey{ID: v.MessageID, Protocol: v.MessageProtocol},
		Published: v.Published, Expires: v.Expires, Sequence: uint64(v.Sequence), SizeBytes: v.SizeBytes,
	}
}

func (r reader) ArchiveEntry(k domain.MessageKey) (domain.ArchiveEntry, error) {
	v, err := r.q.GetArchiveEntry(r.ctx, sqlcgen.GetArchiveEntryParams{MessageID: k.ID, MessageProtocol: k.Protocol})
	if err != nil {
		return domain.ArchiveEntry{}, missing(err)
	}
	return archiveEntry(v), nil
}

func (r reader) NextArchiveEntry(topicID string, start time.Time, after uint64) (domain.ArchiveEntry, bool, error) {
	v, err := r.q.NextArchiveEntry(r.ctx, sqlcgen.NextArchiveEntryParams{TopicID: topicID, Start: start.UTC(), AfterSequence: sqlite.Uint64(after)})
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

func (r reader) ArchiveUsage(topicID string) (messages, bytes int64, err error) {
	v, err := r.q.ArchiveUsage(r.ctx, topicID)
	if err != nil {
		return 0, 0, err
	}
	return v.Messages, v.Bytes, nil
}

func (r reader) NextArchiveMetric() (domain.TopicRecord, bool, error) {
	v, err := r.q.NextArchiveMetric(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.TopicRecord{}, false, nil
	}
	if err != nil {
		return domain.TopicRecord{}, false, err
	}
	topic, err := r.topic(v)
	return topic, err == nil, err
}

func (w writer) PutArchiveEntry(v domain.ArchiveEntry) error {
	return w.q.PutArchiveEntry(w.ctx, sqlcgen.PutArchiveEntryParams{
		TopicID: v.TopicID, MessageID: v.Message.ID, MessageProtocol: v.Message.Protocol,
		Published: v.Published.UTC(), Expires: v.Expires.UTC(), Sequence: sqlite.Uint64(v.Sequence), SizeBytes: v.SizeBytes,
	})
}

func (w writer) DeleteArchiveEntry(k domain.MessageKey) error {
	message, err := w.q.DeleteArchiveEntry(w.ctx, sqlcgen.DeleteArchiveEntryParams{MessageID: k.ID, MessageProtocol: k.Protocol})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return w.q.CollectMessage(w.ctx, sqlcgen.CollectMessageParams(message))
}

func (w writer) DeleteArchiveEntries(topicID string) error {
	messages, err := w.q.DeleteArchiveEntries(w.ctx, topicID)
	if err != nil {
		return err
	}
	for _, message := range messages {
		if err := w.q.CollectMessage(w.ctx, sqlcgen.CollectMessageParams(message)); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) UpdateArchiveRetention(topicID string, days int32, now time.Time) error {
	entries, err := w.q.ArchiveRetentionEntries(w.ctx, topicID)
	if err != nil {
		return err
	}
	retention := time.Duration(days) * 24 * time.Hour
	for _, entry := range entries {
		expires := entry.Published.Add(retention)
		if !entry.Expires.After(now) || !expires.After(now) {
			if err := w.DeleteArchiveEntry(domain.MessageKey{ID: entry.MessageID, Protocol: entry.MessageProtocol}); err != nil {
				return err
			}
			continue
		}
		if err := w.q.SetArchiveEntryExpiration(w.ctx, sqlcgen.SetArchiveEntryExpirationParams{
			MessageID: entry.MessageID, MessageProtocol: entry.MessageProtocol, Expires: expires.UTC(),
		}); err != nil {
			return err
		}
	}
	return nil
}

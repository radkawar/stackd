// Package logs persists typed log groups, streams and original event payloads.
package logs

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"

	domain "stackd/storage/logs"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/logs/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}
func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func (r reader) group(v sqlcgen.LogsGroup) (domain.GroupRecord, error) {
	g := domain.GroupRecord{Key: domain.GroupKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, ID: v.ID, Created: v.Created, Sequence: v.Sequence, RetentionDays: int32(v.RetentionDays)}
	tags, err := r.q.ListTags(r.ctx, v.ID)
	if err != nil {
		return g, err
	}
	g.Tags = make(map[string]string, len(tags))
	for _, tag := range tags {
		g.Tags[tag.Key] = tag.Value
	}
	return g, nil
}
func (r reader) Group(k domain.GroupKey) (domain.GroupRecord, error) {
	v, err := r.q.GetGroup(r.ctx, sqlcgen.GetGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.GroupRecord{}, notFound(err)
	}
	return r.group(v)
}
func (r reader) Groups(q domain.GroupQuery) ([]domain.GroupRecord, error) {
	rows, err := r.q.ListGroups(r.ctx, sqlcgen.ListGroupsParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, AfterName: q.After, Prefix: q.Prefix, ContainsText: q.Contains, Class: q.Class, PageLimit: int64(q.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.GroupRecord, 0, len(rows))
	for _, row := range rows {
		g, err := r.group(row)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}
func stream(v sqlcgen.LogsStream) domain.StreamRecord {
	return domain.StreamRecord{Key: domain.StreamKey{GroupID: v.GroupID, Name: v.Name}, ID: v.ID, Created: v.Created, FirstEvent: v.FirstEvent, LastEvent: v.LastEvent, LastIngestion: v.LastIngestion, EventCount: v.EventCount}
}
func (r reader) Stream(k domain.StreamKey) (domain.StreamRecord, error) {
	v, err := r.q.GetStream(r.ctx, sqlcgen.GetStreamParams{GroupID: k.GroupID, Name: k.Name})
	return stream(v), notFound(err)
}
func (r reader) Streams(q domain.StreamQuery) ([]domain.StreamRecord, error) {
	var rows []sqlcgen.LogsStream
	var err error
	switch {
	case q.ByTime && q.Descending:
		rows, err = r.q.ListStreamsByTimeBackward(r.ctx, sqlcgen.ListStreamsByTimeBackwardParams{GroupID: q.GroupID, AfterName: q.After, AfterTime: q.AfterTime, PageLimit: int64(q.Limit)})
	case q.ByTime:
		rows, err = r.q.ListStreamsByTime(r.ctx, sqlcgen.ListStreamsByTimeParams{GroupID: q.GroupID, AfterName: q.After, AfterTime: q.AfterTime, PageLimit: int64(q.Limit)})
	case q.Descending:
		rows, err = r.q.ListStreamsByNameBackward(r.ctx, sqlcgen.ListStreamsByNameBackwardParams{GroupID: q.GroupID, Prefix: q.Prefix, AfterName: q.After, PageLimit: int64(q.Limit)})
	default:
		rows, err = r.q.ListStreamsByName(r.ctx, sqlcgen.ListStreamsByNameParams{GroupID: q.GroupID, Prefix: q.Prefix, AfterName: q.After, PageLimit: int64(q.Limit)})
	}
	if err != nil {
		return nil, err
	}
	out := make([]domain.StreamRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, stream(v))
	}
	return out, nil
}
func (r reader) Events(q domain.EventQuery) ([]domain.EventRecord, error) {
	c := q.Cursor
	if !q.HasCursor {
		c = domain.EventCursor{Timestamp: -1, Ingestion: -1, Sequence: -1}
		if q.Backward {
			c = domain.EventCursor{Timestamp: math.MaxInt64, Ingestion: math.MaxInt64, Sequence: math.MaxInt64}
		}
	}
	var rows []sqlcgen.LogsEvent
	var err error
	switch {
	case q.StreamID != "" && q.Backward:
		rows, err = r.q.StreamEventsBackward(r.ctx, sqlcgen.StreamEventsBackwardParams{StreamID: q.StreamID, StartTime: q.Start, EndTime: q.End, CursorTime: c.Timestamp, CursorIngestion: c.Ingestion, CursorSequence: c.Sequence, PageLimit: int64(q.Limit)})
	case q.StreamID != "":
		rows, err = r.q.StreamEventsForward(r.ctx, sqlcgen.StreamEventsForwardParams{StreamID: q.StreamID, StartTime: q.Start, EndTime: q.End, CursorTime: c.Timestamp, CursorIngestion: c.Ingestion, CursorSequence: c.Sequence, PageLimit: int64(q.Limit)})
	case q.Backward:
		rows, err = r.q.GroupEventsBackward(r.ctx, sqlcgen.GroupEventsBackwardParams{GroupID: q.GroupID, StartTime: q.Start, EndTime: q.End, CursorTime: c.Timestamp, CursorIngestion: c.Ingestion, CursorSequence: c.Sequence, PageLimit: int64(q.Limit)})
	default:
		rows, err = r.q.GroupEventsForward(r.ctx, sqlcgen.GroupEventsForwardParams{GroupID: q.GroupID, StartTime: q.Start, EndTime: q.End, CursorTime: c.Timestamp, CursorIngestion: c.Ingestion, CursorSequence: c.Sequence, PageLimit: int64(q.Limit)})
	}
	if err != nil {
		return nil, err
	}
	out := make([]domain.EventRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.EventRecord{GroupID: v.GroupID, StreamID: v.StreamID, StreamName: v.StreamName, ID: v.ID, Message: v.Message, EventCursor: domain.EventCursor{Timestamp: v.Timestamp, Ingestion: v.Ingestion, Sequence: v.Sequence}})
	}
	return out, nil
}
func (r reader) StoredBytes(groupID string, start int64) (int64, error) {
	return r.q.StoredBytes(r.ctx, sqlcgen.StoredBytesParams{GroupID: groupID, Timestamp: start})
}
func (w writer) PutGroup(g domain.GroupRecord) error {
	old, err := w.q.GetGroup(w.ctx, sqlcgen.GetGroupParams{Partition: g.Key.Partition, AccountID: g.Key.AccountID, Region: g.Key.Region, Name: g.Key.Name})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && old.ID != g.ID {
		return errors.New("log group identity is immutable")
	}
	if err := w.q.PutGroup(w.ctx, sqlcgen.PutGroupParams{Partition: g.Key.Partition, AccountID: g.Key.AccountID, Region: g.Key.Region, Name: g.Key.Name, ID: g.ID, Created: g.Created, Sequence: g.Sequence, RetentionDays: int64(g.RetentionDays)}); err != nil {
		return err
	}
	if err := w.q.DeleteTags(w.ctx, g.ID); err != nil {
		return err
	}
	for key, value := range g.Tags {
		if err := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{GroupID: g.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteGroup(k domain.GroupKey) error {
	return w.q.DeleteGroup(w.ctx, sqlcgen.DeleteGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
func (w writer) PutStream(v domain.StreamRecord) error {
	old, err := w.q.GetStream(w.ctx, sqlcgen.GetStreamParams{GroupID: v.Key.GroupID, Name: v.Key.Name})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && old.ID != v.ID {
		return errors.New("log stream identity is immutable")
	}
	return w.q.PutStream(w.ctx, sqlcgen.PutStreamParams{GroupID: v.Key.GroupID, Name: v.Key.Name, ID: v.ID, Created: v.Created, FirstEvent: v.FirstEvent, LastEvent: v.LastEvent, LastIngestion: v.LastIngestion, EventCount: v.EventCount})
}
func (w writer) DeleteStream(k domain.StreamKey) error {
	return w.q.DeleteStream(w.ctx, sqlcgen.DeleteStreamParams{GroupID: k.GroupID, Name: k.Name})
}
func (w writer) AppendEvent(v domain.EventRecord) error {
	return w.q.AppendEvent(w.ctx, sqlcgen.AppendEventParams{GroupID: v.GroupID, StreamID: v.StreamID, StreamName: v.StreamName, Sequence: v.Sequence, Timestamp: v.Timestamp, Ingestion: v.Ingestion, ID: v.ID, Message: v.Message})
}

func resourcePolicy(v sqlcgen.LogsResourcePolicy) domain.PolicyRecord {
	return domain.PolicyRecord{
		Key:     domain.PolicyKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, PolicyScope: domain.PolicyScope(v.PolicyScope), Name: v.Name},
		GroupID: v.GroupID.String, Document: v.Document, Updated: v.Updated, Revision: v.Revision,
	}
}
func (r reader) ResourcePolicy(k domain.PolicyKey) (domain.PolicyRecord, error) {
	v, err := r.q.GetResourcePolicy(r.ctx, sqlcgen.GetResourcePolicyParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PolicyScope: string(k.PolicyScope), Name: k.Name})
	return resourcePolicy(v), notFound(err)
}
func (r reader) ResourcePolicies(q domain.PolicyQuery) ([]domain.PolicyRecord, error) {
	rows, err := r.q.ListResourcePolicies(r.ctx, sqlcgen.ListResourcePoliciesParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, PolicyScope: string(q.PolicyScope), AfterName: q.After, ResourceArn: q.ResourceARN, PageLimit: int64(q.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PolicyRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, resourcePolicy(v))
	}
	return out, nil
}
func (w writer) PutResourcePolicy(v domain.PolicyRecord) error {
	if v.Key.PolicyScope == domain.PolicyScopeResource {
		k := domain.GroupKey{Scope: v.Key.Scope}
		k.Name = strings.TrimPrefix(v.Key.Name, k.ARN())
		g, err := w.q.GetGroup(w.ctx, sqlcgen.GetGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
		if err != nil {
			return notFound(err)
		}
		if g.ID != v.GroupID || k.ARN() != v.Key.Name {
			return domain.ErrNotFound
		}
	}
	return w.q.PutResourcePolicy(w.ctx, sqlcgen.PutResourcePolicyParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, PolicyScope: string(v.Key.PolicyScope), Name: v.Key.Name, GroupID: sql.NullString{String: v.GroupID, Valid: v.GroupID != ""}, Document: v.Document, Updated: v.Updated, Revision: v.Revision})
}
func (w writer) DeleteResourcePolicy(k domain.PolicyKey) error {
	return w.q.DeleteResourcePolicy(w.ctx, sqlcgen.DeleteResourcePolicyParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PolicyScope: string(k.PolicyScope), Name: k.Name})
}

var _ domain.Repository = (*Repository)(nil)

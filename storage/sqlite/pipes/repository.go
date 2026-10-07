// Package pipes persists Pipes configuration, checkpoints and accepted work in
// the shared SQLite transaction domain. Source engines retain their own data.
package pipes

import (
	"context"
	"database/sql"
	"errors"
	"time"

	api "stackd/internal/awsapi/pipes"
	domain "stackd/storage/pipes"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/pipes/internal/sqlcgen"
)

type Repository struct {
	db *sql.DB
}

func New(db *sql.DB) *Repository {
	return &Repository{db: db}
}
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, t *sql.Tx) error {
		return fn(reader{ctx: ctx, q: sqlcgen.New(t)})
	})
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, t *sql.Tx) error {
		return fn(writer{reader{ctx: ctx, q: sqlcgen.New(t)}})
	})
}
func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, t *sql.Tx) error {
		return fn(writer{reader{ctx: ctx, q: sqlcgen.New(t)}})
	})
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct {
	reader
}

func (r reader) Context() context.Context {
	return r.ctx
}
func missing(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return e
}
func (r reader) Pipe(k domain.Key) (domain.PipeRecord, error) {
	row, e := r.q.Pipe(r.ctx, sqlcgen.PipeParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if e != nil {
		return domain.PipeRecord{}, missing(e)
	}
	return r.pipe(row)
}
func (r reader) PipeByID(id string) (domain.PipeRecord, error) {
	row, e := r.q.PipeByID(r.ctx, id)
	if e != nil {
		return domain.PipeRecord{}, missing(e)
	}
	return r.pipe(row)
}
func (r reader) Pipes() ([]domain.PipeRecord, error) {
	rows, e := r.q.Pipes(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.PipeRecord, 0, len(rows))
	for _, row := range rows {
		p, e := r.pipe(row)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, nil
}
func (r reader) pipe(v sqlcgen.PipesPipe) (domain.PipeRecord, error) {
	p := domain.PipeRecord{
		CFNOwner:      v.CfnOwner,
		Key:           domain.Key{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name},
		ID:            v.ID,
		Version:       v.Version,
		Description:   v.Description,
		RoleARN:       v.RoleArn,
		SourceARN:     v.SourceArn,
		TargetARN:     v.TargetArn,
		EnrichmentARN: v.EnrichmentArn,
		State:         v.State,
		Desired:       v.Desired,
		Reason:        v.Reason,
		Created:       time.Unix(0, v.CreatedNs).UTC(),
		Modified:      time.Unix(0, v.ModifiedNs).UTC(),
		Due:           time.Unix(0, v.DueNs).UTC(),
		Source: domain.SourceSettings{
			Kind:             v.SourceKind,
			StartingPosition: v.StartingPosition,
			BatchSize:        int32(v.BatchSize),
			WindowSeconds:    int32(v.WindowSeconds),
			MaximumAge:       int32(v.MaximumAge),
			MaximumRetries:   int32(v.MaximumRetries),
			Parallelism:      int32(v.Parallelism),
			AutomaticBisect:  v.AutomaticBisect != 0,
			DLQ:              v.DlqArn,
		},
		EnrichmentTemplate: v.EnrichmentTemplate,
		ParentEventID:      v.ParentEventID,
		Tags:               api.TagMap{},
	}
	if v.StartingTimeNs.Valid {
		p.Source.StartingTime = new(time.Unix(0, v.StartingTimeNs.Int64).UTC())
	}
	tags, e := r.q.Tags(r.ctx, p.ID)
	if e != nil {
		return p, e
	}
	for _, tag := range tags {
		p.Tags[api.TagKey(tag.Key)] = api.TagValue(tag.Value)
	}
	filters, e := r.q.Filters(r.ctx, p.ID)
	if e != nil {
		return p, e
	}
	for _, filter := range filters {
		p.Source.Filters = append(p.Source.Filters, filter.Pattern)
	}
	if e = decodeTarget(v, &p.Target); e != nil {
		return p, e
	}
	if p.EnrichmentHTTP, e = decodeEnrichmentHTTP(v); e != nil {
		return p, e
	}
	resources, e := r.q.EventResources(r.ctx, p.ID)
	if e != nil {
		return p, e
	}
	if len(resources) > 0 && p.Target.EventBridgeEventBusParameters == nil {
		p.Target.EventBridgeEventBusParameters = &api.PipeTargetEventBridgeEventBusParameters{}
	}
	for _, resource := range resources {
		p.Target.EventBridgeEventBusParameters.Resources = append(p.Target.EventBridgeEventBusParameters.Resources, api.ArnOrJsonPath(resource.Arn))
	}
	if e = r.configuration(&p); e != nil {
		return p, e
	}
	return p, nil
}
func (w writer) PutPipe(p domain.PipeRecord) error {
	p = domain.Stored(p)
	v := sqlcgen.PipesPipe{
		CfnOwner:           p.CFNOwner,
		Partition:          p.Key.Partition,
		AccountID:          p.Key.AccountID,
		Region:             p.Key.Region,
		Name:               p.Key.Name,
		ID:                 p.ID,
		Version:            p.Version,
		Description:        p.Description,
		RoleArn:            p.RoleARN,
		SourceArn:          p.SourceARN,
		TargetArn:          p.TargetARN,
		EnrichmentArn:      p.EnrichmentARN,
		State:              p.State,
		Desired:            p.Desired,
		Reason:             p.Reason,
		CreatedNs:          p.Created.UnixNano(),
		ModifiedNs:         p.Modified.UnixNano(),
		DueNs:              p.Due.UnixNano(),
		SourceKind:         p.Source.Kind,
		StartingPosition:   p.Source.StartingPosition,
		BatchSize:          int64(p.Source.BatchSize),
		WindowSeconds:      int64(p.Source.WindowSeconds),
		MaximumAge:         int64(p.Source.MaximumAge),
		MaximumRetries:     int64(p.Source.MaximumRetries),
		Parallelism:        int64(p.Source.Parallelism),
		AutomaticBisect:    boolean(p.Source.AutomaticBisect),
		DlqArn:             p.Source.DLQ,
		EnrichmentTemplate: p.EnrichmentTemplate,
		ParentEventID:      p.ParentEventID,
	}
	if p.Source.StartingTime != nil {
		v.StartingTimeNs = sql.NullInt64{Int64: p.Source.StartingTime.UnixNano(), Valid: true}
	}
	if e := encodeTarget(p.Target, &v); e != nil {
		return e
	}
	if e := encodeEnrichmentHTTP(p.EnrichmentHTTP, &v); e != nil {
		return e
	}
	if e := w.q.PutPipe(w.ctx, sqlcgen.PutPipeParams(v)); e != nil {
		return e
	}
	if e := w.q.DeleteTags(w.ctx, p.ID); e != nil {
		return e
	}
	for k, v := range p.Tags {
		if e := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{PipeID: p.ID, Key: string(k), Value: string(v)}); e != nil {
			return e
		}
	}
	if e := w.q.DeleteFilters(w.ctx, p.ID); e != nil {
		return e
	}
	for i, v := range p.Source.Filters {
		if e := w.q.PutFilter(w.ctx, sqlcgen.PutFilterParams{PipeID: p.ID, Position: int64(i), Pattern: v}); e != nil {
			return e
		}
	}
	if e := w.q.DeleteEventResources(w.ctx, p.ID); e != nil {
		return e
	}
	if p.Target.EventBridgeEventBusParameters != nil {
		for i, v := range p.Target.EventBridgeEventBusParameters.Resources {
			if e := w.q.PutEventResource(w.ctx, sqlcgen.PutEventResourceParams{PipeID: p.ID, Position: int64(i), Arn: string(v)}); e != nil {
				return e
			}
		}
	}
	if e := w.putConfiguration(p); e != nil {
		return e
	}
	return nil
}
func (w writer) DeletePipe(k domain.Key) error {
	return w.q.DeletePipe(w.ctx, sqlcgen.DeletePipeParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
func (r reader) Checkpoints(id string) ([]domain.Checkpoint, error) {
	rows, e := r.q.Checkpoints(r.ctx, id)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Checkpoint, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.Checkpoint{
			PipeID:           v.PipeID,
			ShardID:          v.ShardID,
			ParentID:         v.ParentID,
			AdjacentParentID: v.AdjacentParentID,
			Sequence:         v.Sequence,
			Iterator:         v.Iterator,
			Initialized:      v.Initialized != 0,
			Closed:           v.Closed != 0,
		})
	}
	return out, nil
}
func (w writer) PutCheckpoint(v domain.Checkpoint) error {
	return w.q.PutCheckpoint(w.ctx, sqlcgen.PutCheckpointParams{
		PipeID:           v.PipeID,
		ShardID:          v.ShardID,
		ParentID:         v.ParentID,
		AdjacentParentID: v.AdjacentParentID,
		Sequence:         v.Sequence,
		Iterator:         v.Iterator,
		Initialized:      boolean(v.Initialized),
		Closed:           boolean(v.Closed),
	})
}
func (r reader) KafkaIdentity(id string) (domain.KafkaIdentity, error) {
	row, err := r.q.KafkaIdentity(r.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.KafkaIdentity{}, nil
	}
	return domain.KafkaIdentity{ClusterID: row.ClusterID, TopicID: row.TopicID}, err
}
func (w writer) PutKafkaIdentity(id string, identity domain.KafkaIdentity) error {
	return w.q.PutKafkaIdentity(w.ctx, sqlcgen.PutKafkaIdentityParams{PipeID: id, ClusterID: identity.ClusterID, TopicID: identity.TopicID})
}
func (r reader) Work(id string) ([]domain.Work, error) {
	rows, e := r.q.Work(r.ctx, id)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Work, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.Work{
			ID:         v.ID,
			PipeID:     v.PipeID,
			ShardID:    v.ShardID,
			RecordID:   v.RecordID,
			Sequence:   v.Sequence,
			Receipt:    v.Receipt,
			GroupID:    v.GroupID,
			Ordinal:    v.Ordinal,
			Event:      v.Event,
			Created:    time.Unix(0, v.CreatedNs).UTC(),
			Due:        time.Unix(0, v.DueNs).UTC(),
			Attempts:   int32(v.Attempts),
			BatchLimit: int32(v.BatchLimit),
			Phase:      v.Phase,
			Filtered:   v.Filtered != 0,
			LastError:  v.LastError,
		})
	}
	return out, nil
}
func (w writer) PutWork(v domain.Work) error {
	return w.q.PutWork(w.ctx, sqlcgen.PutWorkParams{
		ID:         v.ID,
		PipeID:     v.PipeID,
		ShardID:    v.ShardID,
		RecordID:   v.RecordID,
		Sequence:   v.Sequence,
		Receipt:    v.Receipt,
		GroupID:    v.GroupID,
		Ordinal:    v.Ordinal,
		Event:      v.Event,
		CreatedNs:  v.Created.UnixNano(),
		DueNs:      v.Due.UnixNano(),
		Attempts:   int64(v.Attempts),
		BatchLimit: int64(v.BatchLimit),
		Phase:      v.Phase,
		Filtered:   boolean(v.Filtered),
		LastError:  v.LastError,
	})
}
func (w writer) DeleteWork(id string) error {
	return w.q.DeleteWork(w.ctx, id)
}
func boolean(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func nullableString[T ~string](v *T) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(*v), Valid: true}
}
func stringPointer[T ~string](v sql.NullString) *T {
	if !v.Valid {
		return nil
	}
	return new(T(v.String))
}
func nullableInteger[T ~int32](v *T) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}
func integerPointer[T ~int32](v sql.NullInt64) *T {
	if !v.Valid {
		return nil
	}
	return new(T(v.Int64))
}
func nullableBool[T ~bool](v *T) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: boolean(bool(*v)), Valid: true}
}
func boolPointer[T ~bool](v sql.NullInt64) *T {
	if !v.Valid {
		return nil
	}
	return new(T(v.Int64 != 0))
}

var _ domain.Repository = (*Repository)(nil)

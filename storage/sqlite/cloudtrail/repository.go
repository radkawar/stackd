// Package cloudtrail persists native trail configuration and delivery references.
package cloudtrail

import (
	"context"
	"database/sql"
	"errors"

	"stackd/internal/scheduler"
	domain "stackd/storage/cloudtrail"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/cloudtrail/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
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
func trailKey(v sqlcgen.CloudtrailTrail) domain.TrailKey {
	return domain.TrailKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}
}
func (r reader) Trail(k domain.TrailKey) (domain.TrailRecord, error) {
	v, err := r.q.GetTrail(r.ctx, sqlcgen.GetTrailParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.TrailRecord{}, notFound(err)
	}
	return r.trail(v)
}
func (r reader) Trails(partition, accountID string) ([]domain.TrailRecord, error) {
	rows, err := r.q.ListTrails(r.ctx, sqlcgen.ListTrailsParams{Partition: partition, AccountID: accountID})
	if err != nil {
		return nil, err
	}
	return r.trails(rows)
}
func (r reader) HasOrganizationTrails(partition string) (bool, error) {
	_, err := r.q.FindOrganizationTrail(r.ctx, partition)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
func (r reader) trails(rows []sqlcgen.CloudtrailTrail) ([]domain.TrailRecord, error) {
	out := make([]domain.TrailRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.trail(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) trail(row sqlcgen.CloudtrailTrail) (domain.TrailRecord, error) {
	v := domain.TrailRecord{Key: trailKey(row), ID: row.ID, Bucket: row.Bucket, Prefix: row.Prefix, LogsGroupARN: row.LogsGroupArn, LogsRoleARN: row.LogsRoleArn,
		IncludeGlobal: row.IncludeGlobal, MultiRegion: row.MultiRegion, RecursiveLogging: row.RecursiveLogging, Logging: row.Logging, LogFileValidation: row.LogFileValidation,
		Created: row.Created, Modified: row.Modified, Started: row.Started, Stopped: row.Stopped, StopAfter: row.StopAfter}
	v.KMSKeyID = row.KmsKeyID
	v.SNSTopicName = row.SnsTopicName
	v.OrganizationID = row.OrganizationID
	tags, err := r.q.ListTags(r.ctx, row.ID)
	if err != nil {
		return domain.TrailRecord{}, err
	}
	if len(tags) > 0 {
		v.Tags = make(map[string]string, len(tags))
		for _, t := range tags {
			v.Tags[t.Key] = t.Value
		}
	}
	basic, err := r.q.ListBasicSelectors(r.ctx, row.ID)
	if err != nil {
		return domain.TrailRecord{}, err
	}
	for _, s := range basic {
		v.Selection.Basic = append(v.Selection.Basic, domain.BasicSelector{ReadOnly: s.ReadOnly, IncludeManagement: s.IncludeManagement})
	}
	excluded, err := r.q.ListExcludedSources(r.ctx, row.ID)
	if err != nil {
		return domain.TrailRecord{}, err
	}
	for _, s := range excluded {
		b := &v.Selection.Basic[s.SelectorPosition]
		b.ExcludedSources = append(b.ExcludedSources, s.Source)
	}
	resources, err := r.q.ListDataResources(r.ctx, row.ID)
	if err != nil {
		return domain.TrailRecord{}, err
	}
	for _, s := range resources {
		b := &v.Selection.Basic[s.SelectorPosition]
		b.DataResources = append(b.DataResources, domain.DataResource{Type: s.Type})
	}
	prefixes, err := r.q.ListDataPrefixes(r.ctx, row.ID)
	if err != nil {
		return domain.TrailRecord{}, err
	}
	for _, s := range prefixes {
		d := &v.Selection.Basic[s.SelectorPosition].DataResources[s.ResourcePosition]
		d.ARNPrefixes = append(d.ARNPrefixes, s.Prefix)
	}
	advanced, err := r.q.ListAdvancedSelectors(r.ctx, row.ID)
	if err != nil {
		return domain.TrailRecord{}, err
	}
	for _, s := range advanced {
		v.Selection.Advanced = append(v.Selection.Advanced, domain.AdvancedSelector{Name: s.Name})
	}
	fields, err := r.q.ListFields(r.ctx, row.ID)
	if err != nil {
		return domain.TrailRecord{}, err
	}
	for _, s := range fields {
		a := &v.Selection.Advanced[s.SelectorPosition]
		a.Fields = append(a.Fields, domain.FieldSelector{Field: s.Field})
	}
	tests, err := r.q.ListTests(r.ctx, row.ID)
	if err != nil {
		return domain.TrailRecord{}, err
	}
	for _, s := range tests {
		f := &v.Selection.Advanced[s.SelectorPosition].Fields[s.FieldPosition]
		f.Tests = append(f.Tests, domain.FieldTest{Operator: s.Operator})
	}
	values, err := r.q.ListTestValues(r.ctx, row.ID)
	if err != nil {
		return domain.TrailRecord{}, err
	}
	for _, s := range values {
		t := &v.Selection.Advanced[s.SelectorPosition].Fields[s.FieldPosition].Tests[s.TestPosition]
		t.Values = append(t.Values, s.Value)
	}
	return v, nil
}
func (w writer) PutTrail(v domain.TrailRecord) error {
	old, err := w.q.GetTrail(w.ctx, sqlcgen.GetTrailParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && old.ID != v.ID {
		return errors.New("CloudTrail trail identity is immutable")
	}
	if err == nil && (old.LogsGroupArn != v.LogsGroupARN || old.LogsRoleArn != v.LogsRoleARN) {
		if err := w.q.DeleteDestinationDeliveries(w.ctx, sqlcgen.DeleteDestinationDeliveriesParams{TrailID: v.ID, Destination: string(domain.DestinationLogs)}); err != nil {
			return err
		}
		if err := w.q.DeleteDestinationStatus(w.ctx, sqlcgen.DeleteDestinationStatusParams{TrailID: v.ID, Destination: string(domain.DestinationLogs)}); err != nil {
			return err
		}
	}
	if err := w.q.PutTrail(w.ctx, sqlcgen.PutTrailParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name,
		ID: v.ID, OrganizationID: v.OrganizationID, Bucket: v.Bucket, Prefix: v.Prefix, KmsKeyID: v.KMSKeyID, SnsTopicName: v.SNSTopicName, LogsGroupArn: v.LogsGroupARN, LogsRoleArn: v.LogsRoleARN, IncludeGlobal: v.IncludeGlobal, MultiRegion: v.MultiRegion, RecursiveLogging: v.RecursiveLogging, Logging: v.Logging, LogFileValidation: v.LogFileValidation,
		Created: v.Created, Modified: v.Modified, Started: v.Started, Stopped: v.Stopped, StopAfter: v.StopAfter}); err != nil {
		return err
	}
	if err := w.q.DeleteTags(w.ctx, v.ID); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{TrailID: v.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteBasicSelectors(w.ctx, v.ID); err != nil {
		return err
	}
	if err := w.q.DeleteAdvancedSelectors(w.ctx, v.ID); err != nil {
		return err
	}
	for i, s := range v.Selection.Basic {
		if err := w.q.PutBasicSelector(w.ctx, sqlcgen.PutBasicSelectorParams{TrailID: v.ID, Position: int64(i), ReadOnly: s.ReadOnly, IncludeManagement: s.IncludeManagement}); err != nil {
			return err
		}
		for j, source := range s.ExcludedSources {
			if err := w.q.PutExcludedSource(w.ctx, sqlcgen.PutExcludedSourceParams{TrailID: v.ID, SelectorPosition: int64(i), Position: int64(j), Source: source}); err != nil {
				return err
			}
		}
		for j, d := range s.DataResources {
			if err := w.q.PutDataResource(w.ctx, sqlcgen.PutDataResourceParams{TrailID: v.ID, SelectorPosition: int64(i), Position: int64(j), Type: d.Type}); err != nil {
				return err
			}
			for k, prefix := range d.ARNPrefixes {
				if err := w.q.PutDataPrefix(w.ctx, sqlcgen.PutDataPrefixParams{TrailID: v.ID, SelectorPosition: int64(i), ResourcePosition: int64(j), Position: int64(k), Prefix: prefix}); err != nil {
					return err
				}
			}
		}
	}
	for i, s := range v.Selection.Advanced {
		if err := w.q.PutAdvancedSelector(w.ctx, sqlcgen.PutAdvancedSelectorParams{TrailID: v.ID, Position: int64(i), Name: s.Name}); err != nil {
			return err
		}
		for j, f := range s.Fields {
			if err := w.q.PutField(w.ctx, sqlcgen.PutFieldParams{TrailID: v.ID, SelectorPosition: int64(i), Position: int64(j), Field: f.Field}); err != nil {
				return err
			}
			for k, t := range f.Tests {
				if err := w.q.PutTest(w.ctx, sqlcgen.PutTestParams{TrailID: v.ID, SelectorPosition: int64(i), FieldPosition: int64(j), Position: int64(k), Operator: t.Operator}); err != nil {
					return err
				}
				for l, value := range t.Values {
					if err := w.q.PutTestValue(w.ctx, sqlcgen.PutTestValueParams{TrailID: v.ID, SelectorPosition: int64(i), FieldPosition: int64(j), TestPosition: int64(k), Position: int64(l), Value: value}); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
func (w writer) DeleteTrail(k domain.TrailKey) error {
	return w.q.DeleteTrail(w.ctx, sqlcgen.DeleteTrailParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
func (r reader) DeliveryStatus(id string, kind domain.DestinationKind) (domain.DeliveryStatus, error) {
	v, err := r.q.GetDeliveryStatus(r.ctx, sqlcgen.GetDeliveryStatusParams{TrailID: id, Destination: string(kind)})
	if err != nil {
		return domain.DeliveryStatus{}, notFound(err)
	}
	return domain.DeliveryStatus{TrailID: v.TrailID, Destination: domain.DestinationKind(v.Destination), LastAttempt: v.LastAttempt, LastSuccess: v.LastSuccess, LastError: v.LastError}, nil
}
func (w writer) PutDeliveryStatus(v domain.DeliveryStatus) error {
	if _, err := w.q.GetTrailByID(w.ctx, v.TrailID); err != nil {
		return notFound(err)
	}
	return w.q.PutDeliveryStatus(w.ctx, sqlcgen.PutDeliveryStatusParams{TrailID: v.TrailID, Destination: string(v.Destination), LastAttempt: v.LastAttempt, LastSuccess: v.LastSuccess, LastError: v.LastError})
}
func (r reader) delivery(v sqlcgen.CloudtrailDelivery) (domain.DeliveryRecord, error) {
	trail, err := r.q.GetTrailByID(r.ctx, v.TrailID)
	if err != nil {
		return domain.DeliveryRecord{}, notFound(err)
	}
	return domain.DeliveryRecord{ID: v.ID, OrganizationID: v.OrganizationID, Trail: trailKey(trail), TrailID: v.TrailID, Destination: domain.DestinationKind(v.Destination), AccountID: v.AccountID, Region: v.Region,
		Bucket: v.Bucket, ObjectKey: v.ObjectKey, LogsGroupARN: v.LogsGroupArn, LogsRoleARN: v.LogsRoleArn, Created: v.Created, Due: v.Due, Expires: v.Expires,
		Sealed: v.Sealed, EventCount: int(v.EventCount), Attempts: int(v.Attempts), Version: uint64(v.Version)}, nil
}
func (r reader) Delivery(id string) (domain.DeliveryRecord, error) {
	v, err := r.q.GetDelivery(r.ctx, id)
	if err != nil {
		return domain.DeliveryRecord{}, notFound(err)
	}
	return r.delivery(v)
}
func (r reader) OpenDelivery(trailID, accountID, region string, kind domain.DestinationKind) (domain.DeliveryRecord, error) {
	v, err := r.q.OpenDelivery(r.ctx, sqlcgen.OpenDeliveryParams{TrailID: trailID, AccountID: accountID, Region: region, Destination: string(kind)})
	if err != nil {
		return domain.DeliveryRecord{}, notFound(err)
	}
	return r.delivery(v)
}
func (r reader) DeliveryEventIDs(id string) ([]string, error) {
	if _, err := r.q.GetDelivery(r.ctx, id); err != nil {
		return nil, notFound(err)
	}
	return r.q.ListDeliveryEventIDs(r.ctx, id)
}
func (r reader) NextDelivery() (scheduler.Job, bool, error) {
	v, err := r.q.NextDelivery(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: v.ID, Due: v.Due, Version: uint64(v.Version)}, true, nil
}
func (w writer) PutDelivery(v domain.DeliveryRecord) error {
	trail, err := w.q.GetTrailByID(w.ctx, v.TrailID)
	if err != nil {
		return notFound(err)
	}
	if trailKey(trail) != v.Trail {
		return domain.ErrNotFound
	}
	old, err := w.q.GetDelivery(w.ctx, v.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && old.TrailID != v.TrailID {
		return errors.New("CloudTrail delivery identity is immutable")
	}
	return w.q.PutDelivery(w.ctx, sqlcgen.PutDeliveryParams{ID: v.ID, OrganizationID: v.OrganizationID, TrailID: v.TrailID, Destination: string(v.Destination), AccountID: v.AccountID, Region: v.Region,
		Bucket: v.Bucket, ObjectKey: v.ObjectKey, LogsGroupArn: v.LogsGroupARN, LogsRoleArn: v.LogsRoleARN, Created: v.Created, Due: v.Due, Expires: v.Expires, Sealed: v.Sealed,
		EventCount: int64(v.EventCount), Attempts: int64(v.Attempts), Version: sqlite.Uint64(v.Version)})
}
func (w writer) AppendDeliveryEvent(id, eventID string) error {
	if _, err := w.q.GetDelivery(w.ctx, id); err != nil {
		return notFound(err)
	}
	return w.q.AppendDeliveryEvent(w.ctx, sqlcgen.AppendDeliveryEventParams{DeliveryID: id, EventID: eventID})
}
func (w writer) DeleteDelivery(id string) error { return w.q.DeleteDelivery(w.ctx, id) }

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}

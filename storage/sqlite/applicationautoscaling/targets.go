package applicationautoscaling

import (
	"database/sql"
	"errors"
	"sort"
	"time"

	api "stackd/internal/awsapi/applicationautoscaling"
	domain "stackd/storage/applicationautoscaling"
	"stackd/storage/sqlite/applicationautoscaling/internal/sqlcgen"
)

func (r reader) Target(key domain.TargetKey) (domain.TargetRecord, error) {
	row, err := r.q.GetTarget(r.ctx, sqlcgen.GetTargetParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension})
	if err != nil {
		return domain.TargetRecord{}, missing(err)
	}
	return r.target(row)
}
func (r reader) TargetByARN(scope domain.Scope, arn string) (domain.TargetRecord, error) {
	row, err := r.q.GetTargetByARN(r.ctx, sqlcgen.GetTargetByARNParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, TargetArn: sql.NullString{String: arn, Valid: true}})
	if err != nil {
		return domain.TargetRecord{}, missing(err)
	}
	return r.target(row)
}
func (r reader) Targets(q domain.TargetQuery) ([]domain.TargetRecord, error) {
	from := listCursor(q.From)
	rows, err := r.q.ListTargets(r.ctx, sqlcgen.ListTargetsParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, Namespace: q.Namespace, FilterDimension: q.Dimension, HasNames: flag(len(q.ResourceIDs) != 0), Names: namesJSON(q.ResourceIDs), RowLimit: rowLimit(q.Limit), FromResourceID: from.ResourceID, FromDimension: from.Dimension})
	if err != nil {
		return nil, err
	}
	out := make([]domain.TargetRecord, 0, len(rows))
	for _, row := range rows {
		record, err := r.target(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (r reader) TargetKeys(partition, accountID string) ([]domain.TargetKey, error) {
	rows, err := r.q.ListTargetKeys(r.ctx, sqlcgen.ListTargetKeysParams{Partition: partition, AccountID: accountID})
	if err != nil {
		return nil, err
	}
	var out []domain.TargetKey
	for _, row := range rows {
		out = append(out, targetKey(row.Partition, row.AccountID, row.Region, row.Namespace, row.ResourceID, row.Dimension))
	}
	return out, nil
}
func (r reader) target(row sqlcgen.AasTarget) (domain.TargetRecord, error) {
	out := domain.TargetRecord{Ownership: row.Ownership, ID: row.NativeID, Key: targetKey(row.Partition, row.AccountID, row.Region, row.Namespace, row.ResourceID, row.Dimension), OriginEventID: row.OriginEventID, ReconcileAt: row.ReconcileAt.Time,
		Data: api.ScalableTarget{CreationTime: timePointer(row.CreationTime), MaxCapacity: intPointer[api.ResourceCapacity](row.MaxCapacity), MinCapacity: intPointer[api.ResourceCapacity](row.MinCapacity), PredictedCapacity: intPointer[api.ResourceCapacity](row.PredictedCapacity), ResourceId: stringPointer[api.ResourceIdMaxLen1600](row.DataResourceID), RoleARN: stringPointer[api.ResourceIdMaxLen1600](row.RoleArn), ScalableDimension: stringPointer[api.ScalableDimension](row.DataDimension), ScalableTargetARN: stringPointer[api.XmlString](row.TargetArn), ServiceNamespace: stringPointer[api.ServiceNamespace](row.DataNamespace)}}
	if row.HasSuspendedState {
		out.Data.SuspendedState = &api.SuspendedState{DynamicScalingInSuspended: boolPointer[api.ScalingSuspended](row.SuspendedIn), DynamicScalingOutSuspended: boolPointer[api.ScalingSuspended](row.SuspendedOut), ScheduledScalingSuspended: boolPointer[api.ScalingSuspended](row.SuspendedScheduled)}
	}
	if row.HasTags {
		out.Tags = make(api.TagMap)
	}
	tags, err := r.q.ListTargetTags(r.ctx, row.TargetPk)
	if err != nil {
		return domain.TargetRecord{}, err
	}
	for _, tag := range tags {
		out.Tags[api.TagKey(tag.Key)] = api.TagValue(tag.Value)
	}
	return out, nil
}
func (r reader) NextTargetReconcile() (domain.TargetKey, time.Time, bool, error) {
	row, err := r.q.NextTargetReconcile(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.TargetKey{}, time.Time{}, false, nil
	}
	if err != nil {
		return domain.TargetKey{}, time.Time{}, false, err
	}
	return targetKey(row.Partition, row.AccountID, row.Region, row.Namespace, row.ResourceID, row.Dimension), row.ReconcileAt.Time, true, nil
}
func (w writer) PutTarget(record domain.TargetRecord) error {
	key, data := record.Key, record.Data
	p := sqlcgen.PutTargetParams{Ownership: record.Ownership, Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension, NativeID: record.ID, OriginEventID: record.OriginEventID, ReconcileAt: deadline(record.ReconcileAt), CreationTime: nullableTime(data.CreationTime), MaxCapacity: nullableInt(data.MaxCapacity), MinCapacity: nullableInt(data.MinCapacity), PredictedCapacity: nullableInt(data.PredictedCapacity), DataResourceID: nullableString(data.ResourceId), RoleArn: nullableString(data.RoleARN), DataDimension: nullableString(data.ScalableDimension), TargetArn: nullableString(data.ScalableTargetARN), DataNamespace: nullableString(data.ServiceNamespace), HasSuspendedState: data.SuspendedState != nil, HasTags: record.Tags != nil}
	if state := data.SuspendedState; state != nil {
		p.SuspendedIn = nullableBool(state.DynamicScalingInSuspended)
		p.SuspendedOut = nullableBool(state.DynamicScalingOutSuspended)
		p.SuspendedScheduled = nullableBool(state.ScheduledScalingSuspended)
	}
	row, err := w.q.PutTarget(w.ctx, p)
	if err != nil {
		return err
	}
	if err := w.q.DeleteTargetTags(w.ctx, row.TargetPk); err != nil {
		return err
	}
	keys := make([]string, 0, len(record.Tags))
	for key := range record.Tags {
		keys = append(keys, string(key))
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := w.q.InsertTargetTag(w.ctx, sqlcgen.InsertTargetTagParams{TargetPk: row.TargetPk, Key: key, Value: string(record.Tags[api.TagKey(key)])}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteTarget(key domain.TargetKey) error {
	if err := w.q.DeleteTargetPolicies(w.ctx, sqlcgen.DeleteTargetPoliciesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension}); err != nil {
		return err
	}
	if err := w.q.DeleteTargetSchedules(w.ctx, sqlcgen.DeleteTargetSchedulesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension}); err != nil {
		return err
	}
	return w.q.DeleteTarget(w.ctx, sqlcgen.DeleteTargetParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension})
}

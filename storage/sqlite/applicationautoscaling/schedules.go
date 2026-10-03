package applicationautoscaling

import (
	"database/sql"
	"errors"
	"time"

	api "stackd/internal/awsapi/applicationautoscaling"
	domain "stackd/storage/applicationautoscaling"
	"stackd/storage/sqlite/applicationautoscaling/internal/sqlcgen"
)

func (r reader) Schedule(key domain.ScheduleKey) (domain.ScheduleRecord, error) {
	row, err := r.q.GetSchedule(r.ctx, sqlcgen.GetScheduleParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension, Name: key.Name})
	if err != nil {
		return domain.ScheduleRecord{}, missing(err)
	}
	return schedule(row), nil
}
func (r reader) Schedules(q domain.ScheduleQuery) ([]domain.ScheduleRecord, error) {
	from := listCursor(q.From)
	rows, err := r.q.ListSchedules(r.ctx, sqlcgen.ListSchedulesParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, Namespace: q.Namespace, FilterResourceID: q.ResourceID, FilterDimension: q.Dimension, HasNames: flag(len(q.Names) != 0), Names: namesJSON(q.Names), RowLimit: rowLimit(q.Limit), FromResourceID: from.ResourceID, FromDimension: from.Dimension, FromName: from.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ScheduleRecord, len(rows))
	for i, row := range rows {
		out[i] = schedule(row)
	}
	return out, nil
}
func schedule(row sqlcgen.AasSchedule) domain.ScheduleRecord {
	out := domain.ScheduleRecord{Key: domain.ScheduleKey{TargetKey: targetKey(row.Partition, row.AccountID, row.Region, row.Namespace, row.ResourceID, row.Dimension), Name: row.Name}, OriginEventID: row.OriginEventID, NextDue: row.NextDue.Time,
		Data: api.ScheduledAction{CreationTime: timePointer(row.CreationTime), EndTime: timePointer(row.EndTime), StartTime: timePointer(row.StartTime), Timezone: stringPointer[api.ResourceIdMaxLen1600](row.Timezone), ResourceId: stringPointer[api.ResourceIdMaxLen1600](row.DataResourceID), ScalableDimension: stringPointer[api.ScalableDimension](row.DataDimension), ServiceNamespace: stringPointer[api.ServiceNamespace](row.DataNamespace), Schedule: stringPointer[api.ResourceIdMaxLen1600](row.Schedule), ScheduledActionARN: stringPointer[api.ResourceIdMaxLen1600](row.ActionArn), ScheduledActionName: stringPointer[api.ScheduledActionName](row.ActionName)},
	}
	if row.HasAction {
		out.Data.ScalableTargetAction = &api.ScalableTargetAction{MinCapacity: intPointer[api.ResourceCapacity](row.MinCapacity), MaxCapacity: intPointer[api.ResourceCapacity](row.MaxCapacity)}
	}
	return out
}
func (r reader) NextSchedule() (domain.ScheduleKey, time.Time, bool, error) {
	row, err := r.q.NextSchedule(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ScheduleKey{}, time.Time{}, false, nil
	}
	if err != nil {
		return domain.ScheduleKey{}, time.Time{}, false, err
	}
	key := domain.ScheduleKey{TargetKey: targetKey(row.Partition, row.AccountID, row.Region, row.Namespace, row.ResourceID, row.Dimension), Name: row.Name}
	return key, row.NextDue.Time, true, nil
}
func (w writer) PutSchedule(record domain.ScheduleRecord) error {
	key, data := record.Key, record.Data
	p := sqlcgen.PutScheduleParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension, Name: key.Name, OriginEventID: record.OriginEventID, NextDue: deadline(record.NextDue), CreationTime: nullableTime(data.CreationTime), StartTime: nullableTime(data.StartTime), EndTime: nullableTime(data.EndTime), Timezone: nullableString(data.Timezone), DataResourceID: nullableString(data.ResourceId), DataDimension: nullableString(data.ScalableDimension), DataNamespace: nullableString(data.ServiceNamespace), Schedule: nullableString(data.Schedule), ActionArn: nullableString(data.ScheduledActionARN), ActionName: nullableString(data.ScheduledActionName), HasAction: data.ScalableTargetAction != nil}
	if action := data.ScalableTargetAction; action != nil {
		p.MinCapacity = nullableInt(action.MinCapacity)
		p.MaxCapacity = nullableInt(action.MaxCapacity)
	}
	return w.q.PutSchedule(w.ctx, p)
}
func (w writer) DeleteSchedule(key domain.ScheduleKey) error {
	return w.q.DeleteSchedule(w.ctx, sqlcgen.DeleteScheduleParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension, Name: key.Name})
}
